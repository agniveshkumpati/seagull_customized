/*
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * (c)Copyright 2006 Hewlett-Packard Development Company, LP.
 *
 */

#include "CryptExternalMethods.hpp"
#include "Utils.hpp"
#include "string_t.hpp"
#include <regex.h>
#include <cstring>

#ifdef DEBUG_MODE
#define GEN_DEBUG(l,a) iostream_error << a << iostream_endl << iostream_flush ; 
#else
#define GEN_DEBUG(l,a) 
#endif

#define GEN_ERROR(l,a) iostream_error << a << iostream_endl << iostream_flush ; 



extern char *stristr (const char *s1, const char *s2) ;
extern int createAuthHeaderMD5(char * user, char * password, char * method,
                               char * uri, char * msgbody, char * auth, 
                               char * algo, char * result);
extern int createAuthHeaderAKAv1MD5(char * user, char * OP,
                                    char * AMF,
                                    char * K,
                                    char * method,
                                    char * uri, char * msgbody, char * auth, char *algo,
                                    char * result);


char* external_find_text_value (char *P_buf, char *P_field) {

  if ((P_buf == NULL) || (P_field == NULL))
    return NULL;


  char *L_value = NULL ;

  regex_t    L_reg_expr ;
  int        L_status ;
  char       L_buffer[100];
  regmatch_t L_pmatch[3] ;
  size_t     L_size = 0 ;

  string_t   L_string = "" ;
  
  L_string  = "([[:blank:]]*" ;
  L_string += P_field ;
  L_string += "[[:blank:]]*=[[:blank:]]*)([^;]+)";

  L_status = regcomp (&L_reg_expr, 
		      L_string.c_str(),
		      REG_EXTENDED) ;

  if (L_status != 0) {
    regerror(L_status, &L_reg_expr, L_buffer, 100);
    regfree (&L_reg_expr) ;
  } else {
  
    L_status = regexec (&L_reg_expr, P_buf, 3, L_pmatch, 0) ;
    regfree (&L_reg_expr) ;
    if (L_status == 0) {
      L_size = L_pmatch[2].rm_eo - L_pmatch[2].rm_so ;
      ALLOC_TABLE(L_value, char*, sizeof(char), L_size+1);
      memcpy(L_value, &(P_buf[L_pmatch[2].rm_so]), L_size);
      L_value[L_size]='\0' ;
    } 
  }
  return (L_value);
}

typedef struct _crypto_args_string {
  char * m_user; 
  char * m_password; 
  char * m_method;
  char * m_uri; 
  char * m_auth; 
  int    m_algo_id;
  char * m_algo ;
  char * m_aka_k ;
  char * m_aka_op ;
  char * m_aka_amf ;
  char * m_shared_secret ;
  char * m_realm ;		//AGNI - Added newly for Diameter Digest-HA1 AVP calculation
} T_CryptoArgsStr, *T_pCryptoArgsStr ;


static const T_CryptoArgsStr Crypto_Args_Str_init = {
  NULL,
  NULL , 
  NULL,
  NULL,
  NULL, 
  -1,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL,
  NULL			//AGNI - Added newly for Diameter Digest-HA1 AVP calculation 
} ;


int check_algorithm(char * auth) {
  
  char algo[32]="MD5";
  char *start, *end;
  
  if ((start = stristr(auth, "Digest")) == NULL) {
    return (-1);
  }
  
  if ((start = stristr(auth, "algorithm=")) != NULL) {
    start = start + strlen("algorithm=");
    if (*start == '"') { start++; }
    end = start + strcspn(start, " ,\"\r\n");
    strncpy(algo, start, end - start);
    algo[end - start] ='\0';
  }
  
  if (strncasecmp(algo, "MD5", 3)==0) {
    return (0);
  } else if (strncasecmp(algo, "AKAv1-MD5", 9)==0) {
    return (1);
  } else {
    return (-1) ;
  }
}

int crypto_args_analysis (T_pValueData  P_args, T_pCryptoArgsStr P_result) {

  int             L_ret = 0 ;

  *P_result = Crypto_Args_Str_init ;
  P_result->m_user = external_find_text_value((char*)P_args->m_value.m_val_binary.m_value,
                                             (char*)"username")  ;
  if (P_result->m_user == NULL ) {
    GEN_ERROR(E_GEN_FATAL_ERROR,
              "user no defined in format of the action: set-value format=\"username=.. ");
    L_ret = -1;
    return (L_ret);
  }
  
  P_result->m_method = external_find_text_value((char*)P_args->m_value.m_val_binary.m_value,
                                                (char*)"method")  ;
  if (P_result->m_method == NULL ) {
    GEN_ERROR(E_GEN_FATAL_ERROR,
              "method no defined in format of the action: set-value format=\"method=.. ");
    L_ret = -1;
    return (L_ret);
  }
  
  P_result->m_uri = external_find_text_value((char*)P_args->m_value.m_val_binary.m_value,
                                        (char*)"uri")  ;
  if (P_result->m_uri == NULL ) {
    GEN_ERROR(E_GEN_FATAL_ERROR,
              "uri no defined in format of the action: set-value format=\"uri=.. ");
    L_ret = -1;
    return (L_ret);
  }

  P_result->m_auth = external_find_text_value((char*)P_args->m_value.m_val_binary.m_value,
                                              (char*)"auth")  ;
  if (P_result->m_auth == NULL ) {
    GEN_ERROR(E_GEN_FATAL_ERROR,
              "auth no defined in format of the action: set-value format=\"auth=.. ");
    L_ret = -1;
    return (L_ret);
  }

  P_result->m_algo_id = check_algorithm(P_result->m_auth);
  if (P_result->m_algo_id == -1 ) {
    GEN_ERROR(E_GEN_FATAL_ERROR,
              "algorithm not defined (MD5 or AKA)");
    L_ret = -1;
    return (L_ret);
  }

  // MD5 only
  if (P_result->m_algo_id == 0) { // MD5 

    ALLOC_TABLE(P_result->m_algo, char*, sizeof(char), 4);
    strcpy(P_result->m_algo, (char*)"MD5");

    P_result->m_password = external_find_text_value((char*)P_args->m_value.m_val_binary.m_value,
                                                    (char*)"password")  ;
    if (P_result->m_password == NULL ) {
      GEN_ERROR(E_GEN_FATAL_ERROR,
                "password no defined in format of the action: set-value format=\"password=...");
      L_ret = -1;
      return (L_ret);
    }

    
  } else {

    ALLOC_TABLE(P_result->m_algo, char*, sizeof(char), 10);
    strcpy(P_result->m_algo, (char*)"AKAv1-MD5");

    // AKA only
    P_result->m_aka_op = external_find_text_value((char*)P_args->m_value.m_val_binary.m_value,
                                                  (char*)"aka_op")  ;
    if (P_result->m_aka_op == NULL ) {
      GEN_ERROR(E_GEN_FATAL_ERROR,
                "aka_op no defined in format of the action: set-value format=\"aka_op=...");
      L_ret = -1;
      return (L_ret);
    }
    
    P_result->m_aka_amf = external_find_text_value((char*)P_args->m_value.m_val_binary.m_value,
                                                   (char*)"aka_amf")  ;
    if (P_result->m_aka_amf == NULL ) {
      GEN_ERROR(E_GEN_FATAL_ERROR,
                "aka_amf no defined in format of the action: set-value format=\"aka_amf=...");
      L_ret = -1;
      return (L_ret);
    }
    
    P_result->m_aka_k = external_find_text_value((char*)P_args->m_value.m_val_binary.m_value,
                                        (char*)"aka_k")  ;
    if (P_result->m_aka_k == NULL ) {
      GEN_ERROR(E_GEN_FATAL_ERROR,
                "aka_k no defined in format of the action: set-value format=\"aka_k=...");
      L_ret = -1;
      return (L_ret);
    }

  }
  return (L_ret);
}


int crypto_method (T_pValueData  P_msgPart,
                   T_pValueData  P_args,
                   T_pValueData  P_result) {
  
  GEN_DEBUG(1, "AGNI crypto_method start");
  int             L_ret    = 0    ;
  T_CryptoArgsStr L_crypto ;
  char            L_result [2049] ;

  L_ret = crypto_args_analysis(P_args, &L_crypto);
  if (L_ret != -1) {
    if (L_crypto.m_algo_id == 0) {
      L_ret = createAuthHeaderMD5(L_crypto.m_user,
                                  L_crypto.m_password,
                                  L_crypto.m_method,
                                  L_crypto.m_uri,
                                  (char*)P_msgPart->m_value.m_val_binary.m_value,
                                  L_crypto.m_auth,
                                  L_crypto.m_algo,
                                  L_result);
    } else {
      L_ret = createAuthHeaderAKAv1MD5(L_crypto.m_user, 
                                       L_crypto.m_aka_op,
                                       L_crypto.m_aka_amf,
                                       L_crypto.m_aka_k,
                                       L_crypto.m_method,
                                       L_crypto.m_uri,
                                       (char*)P_msgPart->m_value.m_val_binary.m_value,
                                       L_crypto.m_auth,
                                       L_crypto.m_algo,
                                       L_result);
    }
    if (L_ret == 1) {
      P_result->m_type = E_TYPE_STRING ;
      ALLOC_TABLE(P_result->m_value.m_val_binary.m_value,
                  unsigned char*,
                  sizeof(unsigned char),
                  strlen(L_result));      
      P_result->m_value.m_val_binary.m_size = strlen(L_result);
      memcpy(P_result->m_value.m_val_binary.m_value, L_result, strlen(L_result));
    } else {
      L_ret = -1 ;
    }
  }

  FREE_TABLE(L_crypto.m_user); 
  FREE_TABLE(L_crypto.m_password); 
  FREE_TABLE(L_crypto.m_method);
  FREE_TABLE(L_crypto.m_uri); 
  FREE_TABLE(L_crypto.m_auth); 
  FREE_TABLE(L_crypto.m_algo );
  FREE_TABLE(L_crypto.m_aka_k );
  FREE_TABLE(L_crypto.m_aka_op );
  FREE_TABLE(L_crypto.m_aka_amf );
  FREE_TABLE(L_crypto.m_shared_secret );

  GEN_DEBUG(1, "AGNI crypto_method end");
  return (L_ret);
}

/** Analyze arguments for radius protocol 
  * \param P_args uses to determine the shared secret 
  * \param P_result contains the shared secret
  * \return 0 if OK
  */
int crypto_args_analysis_radius (T_pValueData  P_args, T_pCryptoArgsStr P_result) {

  int             L_ret = 0 ;

  *P_result = Crypto_Args_Str_init ;
  if (P_args->m_value.m_val_binary.m_size > 0) {
    P_result->m_shared_secret = external_find_text_value((char*)P_args->m_value.m_val_binary.m_value,
                                                         (char*)"shared_secret")  ;
  }
  return (L_ret);
}

void convertHashToHex(unsigned char *_b, unsigned char *_h)
{
  unsigned short i;
  unsigned char j;

  for (i = 0; i < 16; i++) {
    j = (_b[i] >> 4) & 0xf;
    if (j <= 9) {
      _h[i * 2] = (j + '0');
    } else {
      _h[i * 2] = (j + 'a' - 10);
    }
    j = _b[i] & 0xf;
    if (j <= 9) {
      _h[i * 2 + 1] = (j + '0');
    } else {
      _h[i * 2 + 1] = (j + 'a' - 10);
    }
  };
  _h[32] = '\0';
}



/** Authentication algorithm for radius protocol 
  * \param P_msgPart uses to calculate the key   
  * \param P_args contains the shared secret
  * \param P_result contains the result of this algorithm
  * \return 0 if OK
  */
int create_algo_MD5_radius(char          *  P_msg,
                           int              P_msg_size,
                           char          *  P_shared_secret,
                           unsigned char *  P_result) {
  GEN_DEBUG(1, "AGNI create_algo_MD5_radius start");

  int        L_ret         = 0 ;
  int        L_size_shared = 0 ;
  char       *p, *msg_secret;

  //MD5_CTX    L_Md5Ctx ;
   if (P_shared_secret != NULL) {
    L_size_shared = strlen(P_shared_secret);
  }
  //AGNI - This code has been corrected from original
  //Reference: http://networkconvergence.blogspot.com/2015/11/i-fixed-radius-accounting-request.html
  /*
 *   MD5_Init(&L_Md5Ctx);
 *   if (L_size_shared > 0) {
 *      MD5_Update(&L_Md5Ctx, P_shared_secret, L_size_shared);
 *    }
 *    MD5_Update(&L_Md5Ctx, P_msg, P_msg_size);
 *    MD5_Final(P_result, &L_Md5Ctx);
 **/
  msg_secret = (char *)malloc(P_msg_size + L_size_shared);
  memcpy(msg_secret, P_msg, P_msg_size);
  p = msg_secret + P_msg_size;
  memcpy(p, P_shared_secret, L_size_shared);

  MD5((unsigned char *)msg_secret, P_msg_size + L_size_shared, P_result);
  free(msg_secret);


  GEN_DEBUG(1, "AGNI create_algo_MD5_radius stop");
  return (L_ret);
}


/** Authentication method for radius protocol 
  * \param P_msgPart uses to calculate the key   
  * \param P_args contains the shared secret
  * \param P_result contains the result of this method
  * \return 0 if OK
  */
int crypto_method_radius (T_pValueData  P_msgPart,
                          T_pValueData  P_args,
                          T_pValueData  P_result) {
  GEN_DEBUG(1, "AGNI crypto_method_radius start");
  
  int             L_ret    = 0    ;
  T_CryptoArgsStr L_crypto        ;
  unsigned char   L_result [32]   ;


  L_ret = crypto_args_analysis_radius(P_args, &L_crypto);
  if (L_ret != -1) {
    L_ret =  create_algo_MD5_radius((char*)P_msgPart->m_value.m_val_binary.m_value,
                                    P_msgPart->m_value.m_val_binary.m_size,
                                    L_crypto.m_shared_secret,
                                    L_result);
    if (L_ret != -1) {
      P_result->m_type = E_TYPE_STRING ;
      ALLOC_TABLE(P_result->m_value.m_val_binary.m_value,
                  unsigned char*,
                  sizeof(unsigned char),
                  32);      
      P_result->m_value.m_val_binary.m_size = 32;
      memcpy(P_result->m_value.m_val_binary.m_value, L_result, 32);
    } 
  }

  FREE_TABLE(L_crypto.m_shared_secret );
  GEN_DEBUG(1, "AGNI crypto_method_radius end");
  return (L_ret);
}


/** Author: Agnivesh Kumpati
 *  Analyze arguments for diameter protocol 
 ** \param P_args uses to determine the username, realm, password
 ** \return 0 if OK
 **/
int crypto_args_analysis_diameter (T_pValueData  P_args, T_pCryptoArgsStr P_result) {

  GEN_DEBUG(1, "AGNI crypto_args_analysis_diameter start");

  int             L_ret = 0 ;
  *P_result = Crypto_Args_Str_init ;

  if (P_args->m_value.m_val_binary.m_size > 0) {
    P_result->m_user = external_find_text_value((char*)P_args->m_value.m_val_binary.m_value,
                                                         (char*)"username")  ;
    if (P_result->m_user == NULL ) {
      GEN_ERROR(E_GEN_FATAL_ERROR,
              "username not defined in format of the action: set-value format=\"username=.. ");
      L_ret = -1;
      return (L_ret);
    }

    P_result->m_realm = external_find_text_value((char*)P_args->m_value.m_val_binary.m_value,
                                                         (char*)"realm")  ;
    if (P_result->m_realm == NULL ) {
      GEN_ERROR(E_GEN_FATAL_ERROR,
              "realm not defined in format of the action: set-value format=\"realm=.. ");
      L_ret = -1;
      return (L_ret);
    }

    P_result->m_password = external_find_text_value((char*)P_args->m_value.m_val_binary.m_value,
                                                    (char*)"password")  ;
    if (P_result->m_password == NULL ) {
      GEN_ERROR(E_GEN_FATAL_ERROR,
                "password not defined in format of the action: set-value format=\"password=..");
      L_ret = -1;
      return (L_ret);
    }
  }
  GEN_DEBUG(1, "AGNI crypto_args_analysis_diameter end");
  return (L_ret);
}



/** Author: Agnivesh Kumpati
 *  Authentication algorithm for diameter protocol 
 ** \param P_user, P_realm, P_password contains username, realm, password respectively
 ** \param P_result contains the MD5 Hash of username:realm:password
 ** \return 0 if OK
 **/
int create_algo_MD5_diameter(char          *  P_user,
                           char          *  P_realm,
                           char          *  P_password,
                           char *  P_result) {
  GEN_DEBUG(1, "AGNI create_algo_MD5_diameter start");

  int        L_ret         = 0 ;
  MD5_CTX    L_Md5Ctx ;
  unsigned char ha1[16];
  unsigned char ha1_hex[33];

  GEN_DEBUG(1, "AGNI create_algo_MD5_diameter user = " << P_user << ", realm = " << P_realm << ", pass = " << P_password);

  MD5_Init(&L_Md5Ctx);
  MD5_Update(&L_Md5Ctx, P_user, strlen(P_user));
  MD5_Update(&L_Md5Ctx, ":", 1);
  MD5_Update(&L_Md5Ctx, P_realm, strlen(P_realm));
  MD5_Update(&L_Md5Ctx, ":", 1);
  MD5_Update(&L_Md5Ctx, P_password, strlen(P_password));
  MD5_Final(ha1, &L_Md5Ctx);


  convertHashToHex(&ha1[0], &ha1_hex[0]);
  GEN_DEBUG(1, "AGNI create_algo_MD5_diameter ha1_hex after = " << ha1_hex);
  sprintf(P_result, "%s",ha1_hex);
  /*GEN_DEBUG(1, "AGNI create_algo_MD5_diameter P_result is ");
  for(int i=0; i < 32; i++) {
      printf("%02x",P_result[i]);
  }
  printf("\n");*/

  GEN_DEBUG(1, "AGNI create_algo_MD5_diameter end");
  return (L_ret);
}



/** Author: Agnivesh Kumpati
 ** Creates and return MD5 hash for diameter protocol 
 ** \param P_args contains username, realm and password parameters sent from scenario file
 ** \param P_result contains the MD5 Hash of username:realm:password
 ** \return 0 if OK
 **/
int crypto_method_diameter (T_pValueData  P_msgPart,
                          T_pValueData  P_args,
                          T_pValueData  P_result) {
  GEN_DEBUG(1, "AGNI crypto_method_diameter start");

  int             L_ret    = 0    ;
  T_CryptoArgsStr L_crypto ;
  char            L_result [32] ;

  L_ret = crypto_args_analysis_diameter(P_args, &L_crypto);
  if (L_ret != -1) {
    L_ret =  create_algo_MD5_diameter(L_crypto.m_user,
				      L_crypto.m_realm,
				      L_crypto.m_password,
                                      L_result);
    if (L_ret != -1) {
      P_result->m_type = E_TYPE_STRING ;
      ALLOC_TABLE(P_result->m_value.m_val_binary.m_value,
                  unsigned char*,
                  sizeof(unsigned char),
                  strlen(L_result));
      P_result->m_value.m_val_binary.m_size = strlen(L_result);
      memcpy(P_result->m_value.m_val_binary.m_value, L_result, strlen(L_result));
    }
  }

  //FREE_TABLE(L_crypto.m_user );		// TODO: Double free/Corruption Crash
  FREE_TABLE(L_crypto.m_realm );
  FREE_TABLE(L_crypto.m_password );

  GEN_DEBUG(1, "AGNI crypto_method_diameter end");

  return (L_ret);     
}
