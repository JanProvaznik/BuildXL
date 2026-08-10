#include <EndpointSecurity/EndpointSecurity.h>
#include <stdio.h>
static const char *nm(es_new_client_result_t r){
  switch(r){case ES_NEW_CLIENT_RESULT_SUCCESS:return "SUCCESS";
  case ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT:return "ERR_INVALID_ARGUMENT";
  case ES_NEW_CLIENT_RESULT_ERR_INTERNAL:return "ERR_INTERNAL";
  case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED:return "ERR_NOT_ENTITLED";
  case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED:return "ERR_NOT_PERMITTED (TCC)";
  case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED:return "ERR_NOT_PRIVILEGED (root)";
  case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS:return "ERR_TOO_MANY_CLIENTS";
  default:return "?";}}
int main(void){
  es_client_t *a=NULL,*b=NULL;
  es_new_client_result_t ra = es_new_client(&a, ^(es_client_t *c, const es_message_t *m){(void)c;(void)m;});
  printf("es_new_client              = %d %s\n", ra, nm(ra));
  es_new_client_result_t rb = es_new_descendants_client(&b, ^(es_client_t *c, const es_message_t *m){(void)c;(void)m;});
  printf("es_new_descendants_client  = %d %s\n", rb, nm(rb));
  return 0;
}
