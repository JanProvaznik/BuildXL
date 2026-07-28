// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#ifndef BUILDXL_SANDBOX_MACOS_BOUNDED_QUEUE_H
#define BUILDXL_SANDBOX_MACOS_BOUNDED_QUEUE_H

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <deque>
#include <mutex>
#include <optional>

namespace buildxl {
namespace macos {

/**
 * A bounded multi-producer/single-consumer queue.
 *
 * Unlike buildxl::common::ConcurrentQueue (unbounded), this queue has a hard capacity and reports
 * enqueue failures explicitly. The Endpoint Security callback must never block and must never grow
 * without limit, so when the drain thread falls behind the only options are to block (which risks
 * ES deadline misses and kernel-side drops) or to refuse the item.
 *
 * Refusing is the correct choice here *because* the refusal is observable: the caller turns it into
 * TaintReason::kLocalQueueOverflow, which makes the pip non-cacheable. Silently discarding would be
 * the unsound alternative.
 */
template<typename T>
class BoundedQueue
{
public:
    explicit BoundedQueue(size_t capacity)
        : m_capacity(capacity == 0 ? 1 : capacity)
    {
    }

    /**
     * Attempts to enqueue. Returns false without blocking when the queue is full or closed;
     * the rejection is counted in EnqueueFailures().
     */
    bool TryEnqueue(T &&item)
    {
        return TryEnqueueFor(std::move(item), std::chrono::nanoseconds::zero());
    }

    /**
     * Attempts to enqueue, waiting up to `budget` for the drain thread to make room.
     *
     * The budget exists because dropping an event costs a whole pip (it taints), while waiting a few
     * hundred microseconds costs nothing as long as the wait stays well inside the Endpoint Security
     * message deadline. Callers pass the remaining deadline budget so the wait can never be the
     * reason a deadline is missed. A zero budget degrades to a pure non-blocking try.
     */
    bool TryEnqueueFor(T &&item, std::chrono::nanoseconds budget)
    {
        {
            std::unique_lock<std::mutex> lock(m_mutex);

            if (!m_closed && m_items.size() >= m_capacity && budget > std::chrono::nanoseconds::zero())
            {
                m_backpressureWaits++;
                const auto start = std::chrono::steady_clock::now();
                m_notFull.wait_for(lock, budget, [this] { return m_closed || m_items.size() < m_capacity; });
                m_backpressureNanos += static_cast<uint64_t>(
                    std::chrono::duration_cast<std::chrono::nanoseconds>(
                        std::chrono::steady_clock::now() - start).count());
            }

            if (m_closed || m_items.size() >= m_capacity)
            {
                m_enqueueFailures++;
                return false;
            }

            m_items.push_back(std::move(item));
            if (m_items.size() > m_highWaterMark)
            {
                m_highWaterMark = m_items.size();
            }
        }

        m_notEmpty.notify_one();
        return true;
    }

    /**
     * Blocks until an item is available or the queue is closed and drained.
     * Returns std::nullopt only when the queue is closed and empty.
     */
    std::optional<T> WaitAndDequeue()
    {
        std::unique_lock<std::mutex> lock(m_mutex);
        m_notEmpty.wait(lock, [this] { return !m_items.empty() || m_closed; });

        if (m_items.empty())
        {
            return std::nullopt;
        }

        T item = std::move(m_items.front());
        m_items.pop_front();
        const bool wasFull = m_items.size() + 1 >= m_capacity;
        lock.unlock();

        if (wasFull)
        {
            m_notFull.notify_all();
        }

        return item;
    }

    /**
     * Moves every queued item into `out` in order. Draining in batches keeps the producer's
     * backpressure wait short and amortizes the lock across the whole burst.
     * Returns false only when the queue is closed and empty.
     */
    bool WaitAndDrain(std::deque<T> &out)
    {
        std::unique_lock<std::mutex> lock(m_mutex);
        m_notEmpty.wait(lock, [this] { return !m_items.empty() || m_closed; });

        if (m_items.empty())
        {
            return false;
        }

        out = std::move(m_items);
        m_items.clear();
        lock.unlock();
        m_notFull.notify_all();
        return true;
    }

    /** Wakes the consumer and makes further enqueues fail. Already-queued items are still drained. */
    void Close()
    {
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            m_closed = true;
        }

        m_notEmpty.notify_all();
        m_notFull.notify_all();
    }

    size_t Size() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_items.size();
    }

    size_t Capacity() const { return m_capacity; }

    size_t HighWaterMark() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_highWaterMark;
    }

    uint64_t EnqueueFailures() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_enqueueFailures;
    }

    /** Number of enqueues that had to wait for room. */
    uint64_t BackpressureWaits() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_backpressureWaits;
    }

    /** Total time producers spent waiting for room. */
    uint64_t BackpressureNanos() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_backpressureNanos;
    }

private:
    mutable std::mutex m_mutex;
    std::condition_variable m_notEmpty;
    std::condition_variable m_notFull;
    std::deque<T> m_items;
    const size_t m_capacity;
    size_t m_highWaterMark = 0;
    uint64_t m_enqueueFailures = 0;
    uint64_t m_backpressureWaits = 0;
    uint64_t m_backpressureNanos = 0;
    bool m_closed = false;
};

} // namespace macos
} // namespace buildxl

#endif // BUILDXL_SANDBOX_MACOS_BOUNDED_QUEUE_H
