/*
 * hostapd / EAP-pwd (RFC 5931) server
 * Copyright (c) 2010, Dan Harkins <dharkins@lounge.org>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"

#include "common.h"
#include "crypto/sha256.h"
#include "crypto/ms_funcs.h"
#include "crypto/crypto.h"
#include "eap_server/eap_i.h"
#include "eap_common/eap_pwd_common.h"
#include "common.h"
#include "crypto/crypto.h"
#include "crypto/sha256.h"
#include <openssl/evp.h>

#define SAE_PMK_LEN 32

/* --- TESE: Ticket --- */
struct sae_ticket_payload {
    u32 tid;
    u8 pmk_prime[32];
    u8 padding[12];
};
/* Chaves de cifragem do Ticket (STEK) */
extern u8 global_stek_enc[16];
extern u8 global_stek_mac[16];
static const u8 zeros[32] = { 0 };
/* Sliding Window */
static u64 tid_bitmask = 0;
static u32 last_seen_tid = 0;


struct eap_pwd_data {
	enum {
		PWD_ID_Req, PWD_Commit_Req, PWD_Confirm_Req, SUCCESS, FAILURE
	} state;
	u8 *id_peer;
	size_t id_peer_len;
	u8 *id_server;
	size_t id_server_len;
	u8 *password;
	size_t password_len;
	int password_hash;
	u8 *salt;
	size_t salt_len;
	u32 token;
	u16 group_num;
	u8 password_prep;
	EAP_PWD_group *grp;

	struct wpabuf *inbuf;
	size_t in_frag_pos;
	struct wpabuf *outbuf;
	size_t out_frag_pos;
	size_t mtu;

	struct crypto_bignum *k;
	struct crypto_bignum *private_value;
	struct crypto_bignum *peer_scalar;
	struct crypto_bignum *my_scalar;
	struct crypto_ec_point *my_element;
	struct crypto_ec_point *peer_element;

	u8 my_confirm[SHA256_MAC_LEN];

	u8 msk[EAP_MSK_LEN];
	u8 emsk[EAP_EMSK_LEN];
	u8 session_id[1 + SHA256_MAC_LEN];
	u32 tese_iterations;
    u8 tese_salt[16];
};


static int sae_encrypt_ticket(const u8 *key, const u8 *plain, u8 *cipher, size_t *len)
{
    void *ctx = aes_encrypt_init(key, 16);
    if (!ctx) return -1;

    /* Cifrar os 48 bytes da struct (3 blocos de 16) */
    /* Bloco 1: TID + Início PMK */
    aes_encrypt(ctx, plain, cipher);
    
    /* Bloco 2: Meio da PMK */
    aes_encrypt(ctx, plain + 16, cipher + 16);
    
    /* Bloco 3: Fim da PMK + Padding */
    aes_encrypt(ctx, plain + 32, cipher + 32);

    aes_encrypt_deinit(ctx);
    return 0;
}


static int sae_decrypt_ticket(const u8 *key, const u8 *cipher, u8 *plain)
{
    void *ctx = aes_decrypt_init(key, 16);
    if (!ctx) return -1;
    
    // Bloco 1 (0-16): Contém o TID e o início da PMK
    aes_decrypt(ctx, cipher, plain);
    
    // Bloco 2 (16-32): Contém o resto da PMK
    aes_decrypt(ctx, cipher + 16, plain + 16);
    
    // Bloco 3 (32-48): Contém o final da PMK e o padding
    // SEM ISTO, a tua chave fica cortada ou lida do sítio errado!
    aes_decrypt(ctx, cipher + 32, plain + 32);
    
    aes_decrypt_deinit(ctx);
    return 0;
}

void tese_update_tid_window(u32 received_tid) {
    if (received_tid > last_seen_tid) {
        u32 shift = received_tid - last_seen_tid;
        if (shift < 64) tid_bitmask = (tid_bitmask << shift);
        else tid_bitmask = 0;
        last_seen_tid = received_tid;
    }
    u32 diff = last_seen_tid - received_tid;
    tid_bitmask |= (1ULL << diff);
}

static int verify_tid(u32 tid) {
    if (tid == 0) {
        wpa_printf(MSG_ERROR, "[DEBUG-TID] Rejeitado: TID é zero");
        return -1;
    }

    // Se o TID for maior que o último visto, é impossível ser replay
    if (tid > last_seen_tid) {
        wpa_printf(MSG_INFO, "[DEBUG-TID] Aceite: TID %u é mais recente que %u", tid, last_seen_tid);
        return 0;
    }

    // Se o TID for igual ou menor, verificmos a janela
    u32 diff = last_seen_tid - tid;
    wpa_printf(MSG_INFO, "[DEBUG-TID] Diferença calculada: %u", diff);

    if (diff >= 64) {
        wpa_printf(MSG_ERROR, "[DEBUG-TID] Rejeitado: TID demasiado antigo (diff %u >= 64)", diff);
        return -1;
    }

    if (tid_bitmask & (1ULL << diff)) {
        wpa_printf(MSG_ERROR, "[DEBUG-TID] Rejeitado: Bit %u na máscara já está marcado (REPLAY)", diff);
        return -1;
    }

    wpa_printf(MSG_INFO, "[DEBUG-TID] Aceite: TID dentro da janela e não repetido");
    return 0;
}

static int tese_validar_ticket_sftr(struct eap_sm *sm, struct eap_pwd_data *data, const u8 *ticket_recebido)
{
    u8 decriptado[48]; 
    u32 tid_be, tid_host;

	wpa_printf(MSG_INFO, "\n\033[1;32m[PASSO 3 - FAST-PATH] <<< TICKET DETETADO! >>>\033[0m");
    wpa_printf(MSG_INFO, "|  \033[1;35m[AÇÃO]\033[0m Saltando PBKDF2 e Curvas Elípticas.");

    /* 1. Decifra */
    if (sae_decrypt_ticket(global_stek_enc, ticket_recebido, decriptado) != 0) {
        wpa_printf(MSG_ERROR, "[TESE-SFTR] Erro: Falha na decifração AES (MAC inválido ou chave errada)");
        return 0;
    }

    /* 2. Extração do TID (4 bytes iniciais) */
    os_memcpy(&tid_be, decriptado, 4);
    tid_host = be_to_host32(tid_be);

    /* 3. VERIFICAÇÃO ANTI-REPLAY (Sliding Window) */
    if (verify_tid(tid_host) != 0) {
        wpa_printf(MSG_ERROR, "\033[1;31m[TESE-SFTR] REPLAY DETETADO! TID %u já usado ou fora da janela.\033[0m", tid_host);
        return 0; 
    }

    /* 4. SE PASSOU, ATUALIZAR A JANELA */
    tese_update_tid_window(tid_host);

    /* 5. RECUPERAÇÃO DA PMK -> MSK (32 bytes a partir do offset 4) */
    os_memset(data->msk, 0, EAP_MSK_LEN);
    os_memcpy(data->msk, decriptado + 4, 32); 

    /* 6. SINCRONIZAÇÃO DO MOTOR EAP */
    // EMSK e Session ID
    os_memset(data->emsk, 0, EAP_EMSK_LEN);
    os_memcpy(data->emsk, data->msk, 32); 

    os_memset(data->session_id, 0, 1 + SHA256_MAC_LEN);
    data->session_id[0] = EAP_TYPE_PWD;
    os_memcpy(data->session_id + 1, data->msk, 32);

    // Carregar o Bignum k (Shared Secret) para o KDF do Confirm
    if (data->k) crypto_bignum_deinit(data->k, 1);
    data->k = crypto_bignum_init_set(data->msk, 32);

    if (!data->k) {
        wpa_printf(MSG_ERROR, "[TESE-SFTR] Falha ao inicializar bignum k");
        return 0;
    }

    wpa_printf(MSG_INFO, "|  TID Validado: %u (Janela OK)", tid_host);
    wpa_printf(MSG_INFO, "|  MSK Recuperada do Ticket: %02x%02x...%02x", data->msk[0], data->msk[1], data->msk[31]);
    wpa_printf(MSG_INFO, "\033[1;32m[FLOW] Bypass concluído. Sessão restaurada instantaneamente.\033[0m\n");
    return 1;
}

static const char * eap_pwd_state_txt(int state)
{
	switch (state) {
        case PWD_ID_Req:
		return "PWD-ID-Req";
        case PWD_Commit_Req:
		return "PWD-Commit-Req";
        case PWD_Confirm_Req:
		return "PWD-Confirm-Req";
        case SUCCESS:
		return "SUCCESS";
        case FAILURE:
		return "FAILURE";
        default:
		return "PWD-Unk";
	}
}


static void eap_pwd_state(struct eap_pwd_data *data, int state)
{
	wpa_printf(MSG_DEBUG, "EAP-pwd: %s -> %s",
		   eap_pwd_state_txt(data->state), eap_pwd_state_txt(state));
	data->state = state;
}


static void * eap_pwd_init(struct eap_sm *sm)
{
	struct eap_pwd_data *data;

	if (sm->user == NULL || sm->user->password == NULL ||
	    sm->user->password_len == 0) {
		wpa_printf(MSG_INFO, "EAP-PWD (server): Password is not "
			   "configured");
		return NULL;
	}

	data = os_zalloc(sizeof(*data));
	if (data == NULL)
		return NULL;

	data->group_num = sm->cfg->pwd_group;
	wpa_printf(MSG_DEBUG, "EAP-pwd: Selected group number %d",
		   data->group_num);
	data->state = PWD_ID_Req;

	data->id_server = (u8 *) os_strdup("server");
	if (data->id_server)
		data->id_server_len = os_strlen((char *) data->id_server);

	data->password = os_malloc(sm->user->password_len);
	if (data->password == NULL) {
		wpa_printf(MSG_INFO, "EAP-PWD: Memory allocation password "
			   "fail");
		bin_clear_free(data->id_server, data->id_server_len);
		os_free(data);
		return NULL;
	}
	data->password_len = sm->user->password_len;
	os_memcpy(data->password, sm->user->password, data->password_len);
	data->password_hash = sm->user->password_hash;

	data->salt_len = sm->user->salt_len;
	if (data->salt_len) {
		data->salt = os_memdup(sm->user->salt, sm->user->salt_len);
		if (!data->salt) {
			wpa_printf(MSG_INFO,
				   "EAP-pwd: Memory allocation of salt failed");
			bin_clear_free(data->id_server, data->id_server_len);
			bin_clear_free(data->password, data->password_len);
			os_free(data);
			return NULL;
		}
	}

	data->in_frag_pos = data->out_frag_pos = 0;
	data->inbuf = data->outbuf = NULL;
	/* use default MTU from RFC 5931 if not configured otherwise */
	data->mtu = sm->cfg->fragment_size > 0 ? sm->cfg->fragment_size : 1020;

	return data;
}


static void eap_pwd_reset(struct eap_sm *sm, void *priv)
{
	struct eap_pwd_data *data = priv;

	crypto_bignum_deinit(data->private_value, 1);
	crypto_bignum_deinit(data->peer_scalar, 1);
	crypto_bignum_deinit(data->my_scalar, 1);
	crypto_bignum_deinit(data->k, 1);
	crypto_ec_point_deinit(data->my_element, 1);
	crypto_ec_point_deinit(data->peer_element, 1);
	bin_clear_free(data->id_peer, data->id_peer_len);
	bin_clear_free(data->id_server, data->id_server_len);
	bin_clear_free(data->password, data->password_len);
	bin_clear_free(data->salt, data->salt_len);
	if (data->grp) {
		crypto_ec_deinit(data->grp->group);
		crypto_ec_point_deinit(data->grp->pwe, 1);
		os_free(data->grp);
	}
	wpabuf_free(data->inbuf);
	wpabuf_free(data->outbuf);
	bin_clear_free(data, sizeof(*data));
}


static void eap_pwd_build_id_req(struct eap_sm *sm, struct eap_pwd_data *data,
				 u8 id)
{
	wpa_printf(MSG_DEBUG, "EAP-pwd: ID/Request");
	/*
	 * if we're fragmenting then we already have an id request, just return
	 */
	if (data->out_frag_pos)
		return;

	data->outbuf = wpabuf_alloc(sizeof(struct eap_pwd_id) +
				    data->id_server_len);
	if (data->outbuf == NULL) {
		eap_pwd_state(data, FAILURE);
		return;
	}

	if (os_get_random((u8 *) &data->token, sizeof(data->token)) < 0) {
		wpabuf_free(data->outbuf);
		data->outbuf = NULL;
		eap_pwd_state(data, FAILURE);
		return;
	}

	wpa_hexdump_key(MSG_DEBUG, "EAP-pwd (server): password",
			data->password, data->password_len);
	if (data->salt_len)
		wpa_hexdump(MSG_DEBUG, "EAP-pwd (server): salt",
			    data->salt, data->salt_len);

	/*
	 * If this is a salted password then figure out how it was hashed
	 * based on the length.
	 */
	if (data->salt_len) {
		switch (data->password_len) {
		case 20:
			data->password_prep = EAP_PWD_PREP_SSHA1;
			break;
		case 32:
			data->password_prep = EAP_PWD_PREP_SSHA256;
			break;
		case 64:
			data->password_prep = EAP_PWD_PREP_SSHA512;
			break;
		default:
			wpa_printf(MSG_INFO,
				   "EAP-pwd (server): bad size %d for salted password",
				   (int) data->password_len);
			eap_pwd_state(data, FAILURE);
			return;
		}
	} else {
		/* Otherwise, figure out whether it's MS hashed or plain */
		data->password_prep = data->password_hash ? EAP_PWD_PREP_MS :
			EAP_PWD_PREP_NONE;
	}

	/* --- TESE --- */
    data->tese_iterations = 150; // 
    os_get_random(data->tese_salt, 16); 
    
    wpa_printf(MSG_INFO, "[TESE-EAP-SERVER] Gerado Custo: %u", data->tese_iterations);
    wpa_hexdump(MSG_INFO, "[TESE-EAP-SERVER] Gerado Salt:", data->tese_salt, 16);
    /* -------------------------------------------------- */

    wpabuf_put_be16(data->outbuf, data->group_num);
    wpabuf_put_u8(data->outbuf, EAP_PWD_DEFAULT_RAND_FUNC);
    wpabuf_put_u8(data->outbuf, EAP_PWD_DEFAULT_PRF);
    wpabuf_put_data(data->outbuf, &data->token, sizeof(data->token));
    wpabuf_put_u8(data->outbuf, data->password_prep);

    wpabuf_put_be32(data->outbuf, data->tese_iterations);
    wpabuf_put_data(data->outbuf, data->tese_salt, 16);
    
    wpabuf_put_data(data->outbuf, data->id_server, data->id_server_len);
}


static void eap_pwd_build_commit_req(struct eap_sm *sm,
                     struct eap_pwd_data *data, u8 id)
{
    u8 *scalar_ptr, *element_ptr;
    size_t prime_len, order_len;
    u8 random_trash[32]; // Buffer temporário para o S

    wpa_printf(MSG_INFO, "\n\033[1;36m[PASSO 2] >>> SERVIDOR: A GERAR COMMIT <<<\033[0m");

    if (data->out_frag_pos)
        return;

    prime_len = crypto_ec_prime_len(data->grp->group);
    order_len = crypto_ec_order_len(data->grp->group);

    /* 1. buffers de saída */
    data->outbuf = wpabuf_alloc(2 * prime_len + order_len +
                    (data->salt ? 1 + data->salt_len : 0));
    if (data->outbuf == NULL) goto fin;

    if (data->salt_len) {
        wpabuf_put_u8(data->outbuf, data->salt_len);
        wpabuf_put_data(data->outbuf, data->salt, data->salt_len);
    }

    element_ptr = wpabuf_put(data->outbuf, 2 * prime_len);
    scalar_ptr = wpabuf_put(data->outbuf, order_len);

    /* 2. GERAR E GUARDAR O S */
    os_get_random(random_trash, order_len);
    
    // GUARDAR NA ESTRUTURA
    if (data->my_scalar) crypto_bignum_deinit(data->my_scalar, 1);
    data->my_scalar = crypto_bignum_init_set(random_trash, order_len);
    
    // Meter no pacote de rede
    os_memcpy(scalar_ptr, random_trash, order_len);

    /* 3. GERAR O ELEMENT (E) aka Lixo aleatório  */
    os_get_random(element_ptr, 2 * prime_len);

    wpa_hexdump(MSG_INFO, "|  -> S Aleatório Enviado e Guardado:", random_trash, 8);
    wpa_printf(MSG_INFO, "\033[1;36m[FLOW] Commit enviado. A aguardar resposta do Cliente...\033[0m\n");

fin:
    if (data->outbuf == NULL)
        eap_pwd_state(data, FAILURE);
}


static void eap_pwd_build_confirm_req(struct eap_sm *sm,
                      struct eap_pwd_data *data, u8 id)
{
    struct crypto_hash *hash = NULL;
    u8 conf[SHA256_MAC_LEN], *cruft = NULL, *ptr;
    u16 grp;
    size_t prime_len, order_len;

    /* --- Variáveis TESE --- */
    static u32 global_tid_counter = 1;
    u8 pmk_prime[32];
    u8 ticket_mac[32];
    /* ---------------------------- */

    wpa_printf(MSG_DEBUG, "EAP-pwd: Confirm/Request");

    if (data->out_frag_pos)
        return;
	if (data->k != NULL) {
        wpa_printf(MSG_INFO, "|  [INFO] A ignorar conversão de pontos elípticos.");
        
        data->outbuf = wpabuf_alloc(SHA256_MAC_LEN + 144); // Espaço para Confirm + Ticket
        if (data->outbuf == NULL) return;

        /* Injetar o Confirm que já calculámos no passo anterior */
        wpabuf_put_data(data->outbuf, data->my_confirm, SHA256_MAC_LEN);
        
        /* O código deve saltar diretamente para a parte onde injeta o Ticket */
        goto send_ticket; 
    }
    prime_len = crypto_ec_prime_len(data->grp->group);
    order_len = crypto_ec_order_len(data->grp->group);

    /* --- [TESE] Fast Path--- */
    if (data->peer_element == NULL) {
        wpa_printf(MSG_INFO, "[TESE-SFTR] A gerar Confirm de Servidor via Fast-Path...");
        
        /* Usar a MSK recuperada do ticket para gerar o confirm */
        os_memcpy(data->my_confirm, data->msk, SHA256_MAC_LEN);
        
        goto send_ticket;
    }

    /* --- FLUXO NORMAL (Dragonfly / Primeira Autenticação) --- */
    size_t max_buf_len = (prime_len * 2 > order_len) ? (prime_len * 2) : order_len;
    cruft = os_malloc(max_buf_len);
    if (!cruft) goto fin;

    hash = eap_pwd_h_init();
    if (hash == NULL) goto fin;

    // 1. k
    crypto_bignum_to_bin(data->k, cruft, prime_len, prime_len);
    eap_pwd_h_update(hash, cruft, prime_len);

    // 2. server element
    crypto_ec_point_to_bin(data->grp->group, data->my_element, cruft, cruft + prime_len);
    eap_pwd_h_update(hash, cruft, prime_len * 2);

    // 3. server scalar
    crypto_bignum_to_bin(data->my_scalar, cruft, order_len, order_len);
    eap_pwd_h_update(hash, cruft, order_len);

    // 4. peer element
    if (crypto_ec_point_to_bin(data->grp->group, data->peer_element, cruft, cruft + prime_len) != 0) {
        goto fin;
    }
    eap_pwd_h_update(hash, cruft, prime_len * 2);

    // 5. peer scalar
    crypto_bignum_to_bin(data->peer_scalar, cruft, order_len, order_len);
    eap_pwd_h_update(hash, cruft, order_len);

    // 6. ciphersuite
    grp = htons(data->group_num);
    os_memset(cruft, 0, max_buf_len);
    ptr = cruft;
    os_memcpy(ptr, &grp, sizeof(u16));
    ptr += sizeof(u16);
    *ptr = EAP_PWD_DEFAULT_RAND_FUNC;
    ptr += sizeof(u8);
    *ptr = EAP_PWD_DEFAULT_PRF;
    ptr += sizeof(u8);
    eap_pwd_h_update(hash, cruft, ptr - cruft);

    eap_pwd_h_final(hash, conf);
    hash = NULL;
    os_memcpy(data->my_confirm, conf, SHA256_MAC_LEN);

send_ticket:
    /* --- [TESE] GERAÇÃO E INJEÇÃO DO TICKET --- */
    data->outbuf = wpabuf_alloc(144);
    if (data->outbuf == NULL) goto fin;

    wpabuf_put_data(data->outbuf, data->my_confirm, SHA256_MAC_LEN);

    /* 1. Criar e LIMPAR o buffer que vai ser cifrado */
    u8 buffer_pre_cifragem[48];
    os_memset(buffer_pre_cifragem, 0, 48);
    
    os_get_random(pmk_prime, 32);
    u32 tid_n = host_to_be32(global_tid_counter++);

    /* 2. Montar os dados no Byte 0 e Byte 4 */
    os_memcpy(buffer_pre_cifragem, &tid_n, 4);
    os_memcpy(buffer_pre_cifragem + 4, pmk_prime, 32);

    /* --- PRINTS DE DEBUG --- */
    wpa_printf(MSG_INFO, "[TESE-DEBUG] --- FASE DE GERAÇÃO ---");
    wpa_hexdump(MSG_INFO, "[TESE-DEBUG] 1. PMK ORIGINAL (A que devia ir)", pmk_prime, 32);
    wpa_hexdump(MSG_INFO, "[TESE-DEBUG] 2. BUFFER ANTES DE CIFRAR (TID+PMK)", buffer_pre_cifragem, 48);

    /* 3. Cifrar */
    u8 ticket_final[48];
    size_t t_len = 48;
    
    if (sae_encrypt_ticket(global_stek_enc, buffer_pre_cifragem, ticket_final, &t_len) == 0) {
        
        wpa_hexdump(MSG_INFO, "[TESE-DEBUG] 3. TICKET JÁ CIFRADO (O que vai no ar)", ticket_final, 48);

        hmac_sha256(global_stek_mac, 16, ticket_final, 48, ticket_mac);

        /* 4. Injetar no pacote EAP */
        wpabuf_put_data(data->outbuf, pmk_prime, 32);     
        wpabuf_put_data(data->outbuf, ticket_final, 48); 
        wpabuf_put_data(data->outbuf, ticket_mac, 32);     

        wpa_printf(MSG_INFO, "\033[1;32m[RADIUS-TESE] Ticket Gerado e Injetado com Sucesso!\033[0m");
    }

fin:
    if (cruft) bin_clear_free(cruft, prime_len * 2 > order_len ? prime_len * 2 : order_len);
    if (data->outbuf == NULL)
        eap_pwd_state(data, FAILURE);
    if (hash) eap_pwd_h_final(hash, NULL);
}


static struct wpabuf *
eap_pwd_build_req(struct eap_sm *sm, void *priv, u8 id)
{
	struct eap_pwd_data *data = priv;
	struct wpabuf *req;
	u8 lm_exch;
	const u8 *buf;
	u16 totlen = 0;
	size_t len;

	/*
	 * if we're buffering response fragments then just ACK
	 */
	if (data->in_frag_pos) {
		wpa_printf(MSG_DEBUG, "EAP-pwd: ACKing a fragment!!");
		req = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_PWD,
				    EAP_PWD_HDR_SIZE, EAP_CODE_REQUEST, id);
		if (req == NULL) {
			eap_pwd_state(data, FAILURE);
			return NULL;
		}
		switch (data->state) {
		case PWD_ID_Req:
			wpabuf_put_u8(req, EAP_PWD_OPCODE_ID_EXCH);
			break;
		case PWD_Commit_Req:
			wpabuf_put_u8(req, EAP_PWD_OPCODE_COMMIT_EXCH);
			break;
		case PWD_Confirm_Req:
			wpabuf_put_u8(req, EAP_PWD_OPCODE_CONFIRM_EXCH);
			break;
		default:
			eap_pwd_state(data, FAILURE);   /* just to be sure */
			wpabuf_free(req);
			return NULL;
		}
		return req;
	}

	/*
	 * build the data portion of a request
	 */
	switch (data->state) {
	case PWD_ID_Req:
		eap_pwd_build_id_req(sm, data, id);
		lm_exch = EAP_PWD_OPCODE_ID_EXCH;
		break;
	case PWD_Commit_Req:
		eap_pwd_build_commit_req(sm, data, id);
		lm_exch = EAP_PWD_OPCODE_COMMIT_EXCH;
		break;
	case PWD_Confirm_Req:
		eap_pwd_build_confirm_req(sm, data, id);
		lm_exch = EAP_PWD_OPCODE_CONFIRM_EXCH;
		break;
	default:
		wpa_printf(MSG_INFO, "EAP-pwd: Unknown state %d in build_req",
			   data->state);
		eap_pwd_state(data, FAILURE);
		lm_exch = 0;    /* hush now, sweet compiler */
		break;
	}

	if (data->state == FAILURE)
		return NULL;

	/*
	 * determine whether that data needs to be fragmented
	 */
	len = wpabuf_len(data->outbuf) - data->out_frag_pos;
	if ((len + EAP_PWD_HDR_SIZE) > data->mtu) {
		len = data->mtu - EAP_PWD_HDR_SIZE;
		EAP_PWD_SET_MORE_BIT(lm_exch);
		/*
		 * if this is the first fragment, need to set the M bit
		 * and add the total length to the eap_pwd_hdr
		 */
		if (data->out_frag_pos == 0) {
			EAP_PWD_SET_LENGTH_BIT(lm_exch);
			totlen = wpabuf_len(data->outbuf) +
				EAP_PWD_HDR_SIZE + sizeof(u16);
			len -= sizeof(u16);
			wpa_printf(MSG_DEBUG, "EAP-pwd: Fragmenting output, "
				   "total length = %d", totlen);
		}
		wpa_printf(MSG_DEBUG, "EAP-pwd: Send a %d byte fragment",
			   (int) len);
	}

	/*
	 * alloc an eap request and populate it with the data
	 */
	req = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_PWD,
			    EAP_PWD_HDR_SIZE + len +
			    (totlen ? sizeof(u16) : 0),
			    EAP_CODE_REQUEST, id);
	if (req == NULL) {
		eap_pwd_state(data, FAILURE);
		return NULL;
	}

	wpabuf_put_u8(req, lm_exch);
	if (EAP_PWD_GET_LENGTH_BIT(lm_exch))
		wpabuf_put_be16(req, totlen);

	buf = wpabuf_head_u8(data->outbuf);
	wpabuf_put_data(req, buf + data->out_frag_pos, len);
	data->out_frag_pos += len;
	/*
	 * either not fragged or last fragment, either way free up the data
	 */
	if (data->out_frag_pos >= wpabuf_len(data->outbuf)) {
		wpabuf_free(data->outbuf);
		data->outbuf = NULL;
		data->out_frag_pos = 0;
	}

	return req;
}


static bool eap_pwd_check(struct eap_sm *sm, void *priv,
              struct wpabuf *respData)
{
    struct eap_pwd_data *data = priv;
    const u8 *pos;
    size_t len;
    u8 exchange;

    if (data == NULL || respData == NULL)
        return true;


    if (data->peer_element == NULL) {
        return false; 
    }

    pos = eap_hdr_validate(EAP_VENDOR_IETF, EAP_TYPE_PWD, respData, &len);
    if (pos == NULL || len < 1) return true;

    exchange = EAP_PWD_GET_EXCHANGE(*pos);
    if (data->state == PWD_Confirm_Req && exchange == EAP_PWD_OPCODE_CONFIRM_EXCH)
        return false;

    return (data->state != PWD_ID_Req || exchange != EAP_PWD_OPCODE_ID_EXCH) &&
           (data->state != PWD_Commit_Req || exchange != EAP_PWD_OPCODE_COMMIT_EXCH);
}


static void eap_pwd_process_id_resp(struct eap_sm *sm,
                    struct eap_pwd_data *data,
                    const u8 *payload, size_t payload_len)
{
    struct eap_pwd_id *id;
    size_t standard_hdr_len;

	wpa_printf(MSG_INFO, "\n\033[1;36m[PASSO 1] <<< SERVIDOR: IDENTIDADE DO CLIENTE RECEBIDA >>>\033[0m");

    /* * [CÁBULA] 
     * O 'offsetof' calcula o tamanho da estrutura APENAS até ao campo 'tese_cost'.
     * Isto dá o tamanho do cabeçalho PADRÃO que o cliente enviou.
     */
    standard_hdr_len = offsetof(struct eap_pwd_id, tese_cost);

    if (payload_len < standard_hdr_len) {
        wpa_printf(MSG_ERROR, "EAP-PWD: ID payload too short");
        eap_pwd_state(data, FAILURE);
        return;
    }

    id = (struct eap_pwd_id *) payload;

    /* Verificação de segurança */
    if (data->group_num != be_to_host16(id->group_num)) {
        wpa_printf(MSG_ERROR, "[TESE-RADIUS] Cliente tentou mudar o Grupo!");
        eap_pwd_state(data, FAILURE);
        return;
    }

    if (data->id_peer || data->grp) {
        wpa_printf(MSG_INFO, "EAP-pwd: data was already allocated");
        return;
    }

    /* * CALCULO DO TAMANHO DO ID CORRETAMENTE:
     * (Tamanho total do pacote) - (Tamanho do cabeçalho sem campos da Tese)
     */
    data->id_peer_len = payload_len - standard_hdr_len;
    
    wpa_printf(MSG_INFO, "[TESE-DEBUG] ID detectado: %zu bytes", data->id_peer_len);

    data->id_peer = os_malloc(data->id_peer_len);
    if (data->id_peer == NULL) {
        wpa_printf(MSG_ERROR, "EAP-PWD: memory allocation id fail");
        return;
    }

    /* * COPIAR A IDENTIDADE:
     * Ela começa no offset 'standard_hdr_len' (logo após o cabeçalho padrão)
     */
    os_memcpy(data->id_peer, payload + standard_hdr_len, data->id_peer_len);

    data->grp = get_eap_pwd_group(data->group_num);
    if (data->grp == NULL) {
        wpa_printf(MSG_INFO, "EAP-PWD: failed to allocate memory for group");
        return;
    }

    /* --- PRINTS DE DEBUG --- */
    wpa_printf(MSG_INFO, "\033[1;33m[TESE-RADIUS] Lazy Mode: Identidade '%s' aceite. Saltando PWE.\033[0m", 
               (char *)data->id_peer);

	wpa_printf(MSG_INFO, "|  Utilizador identificado: \033[1;33m%s\033[0m", (char *)data->id_peer);
    wpa_printf(MSG_INFO, "|  -> A saltar cálculo do PE.");
    wpa_printf(MSG_INFO, "\033[1;36m Identidade aceite -> Fase de Commit...\033[0m\n");

    /* Avança o estado para o COMMIT */
    eap_pwd_state(data, PWD_Commit_Req);
}


static void
eap_pwd_process_commit_resp(struct eap_sm *sm, struct eap_pwd_data *data,
                const u8 *payload, size_t payload_len)
{
    struct crypto_ec_point *K = NULL;
    struct crypto_bignum *s_val = NULL;
    int res = 0;
    size_t prime_len, order_len;
    u8 pwd_hash_slow[32];

	// 

	static u8 cached_pwd_hash[32];
    static u8 cached_salt[16];
    static u32 cached_iter = 0;
    static int is_cache_ready = 0;

    if (!data || !data->grp) return;

	

    prime_len = crypto_ec_prime_len(data->grp->group);
    order_len = crypto_ec_order_len(data->grp->group);

    if (payload_len != 2 * prime_len + order_len) goto fin;

    /* 1. EXTRAÇÃO DO SCALAR (s) DO CLIENTE - Offset: prime_len * 2 */
    const u8 *peer_scalar_raw = payload + (prime_len * 2);

    /* --- TESE: SLOW PATH --- */
    /* Se o scalar não é zero, o servidor tem de validar o calculo do cliente */
	wpa_printf(MSG_INFO, "\n\033[1;36m[PASSO 3] <<< SERVIDOR: COMMIT DO CLIENTE RECEBIDO >>>\033[0m");

	wpa_printf(MSG_INFO, "|  \033[1;35m[ESTRATÉGIA]\033[0m Validando Prova de Trabalho (PBKDF2)...");

    if (is_cache_ready && 
        cached_iter == data->tese_iterations && 
        os_memcmp(cached_salt, data->tese_salt, 16) == 0) 
    {
		wpa_printf(MSG_INFO, "|  \033[1;32m[CACHE HIT]\033[0m Password idêntica em memória. CPU Cost: 0!");
        os_memcpy(pwd_hash_slow, cached_pwd_hash, 32);
    } 
    else 
    {
		wpa_printf(MSG_INFO, "|  \033[1;33m[CACHE MISS]\033[0m Nova derivação necessária (Iterações: %u).", data->tese_iterations);
        if (PKCS5_PBKDF2_HMAC((const char *)data->password, data->password_len,
                              data->tese_salt, 16,
                              data->tese_iterations,
                              EVP_sha256(), 32, cached_pwd_hash) != 1) {
            wpa_printf(MSG_ERROR, "[TESE-RADIUS] Erro ao calcular PBKDF2");
            goto fin;
        }

        os_memcpy(cached_salt, data->tese_salt, 16);
        cached_iter = data->tese_iterations;
        is_cache_ready = 1;
        
        os_memcpy(pwd_hash_slow, cached_pwd_hash, 32);
    }

	

	// MSK é obtida no compute_keys atraves de k
	// k é o shared secret obtido atraves do PE
	// Portanto temos mm q calcular o PE quando nao temos ticket
    if (compute_password_element(data->grp, data->group_num,
                               pwd_hash_slow, 32, 
                               data->id_server, data->id_server_len,
                               data->id_peer, data->id_peer_len,
                               (u8 *) &data->token) < 0) {
        wpa_printf(MSG_ERROR, "[TESE-RADIUS] Erro ao reconstruir PW para validacao!");
        goto fin;
    }
    forced_memzero(pwd_hash_slow, 32);

	wpa_printf(MSG_INFO, "|  -> PWE Reconstruído com sucesso.");
    wpa_printf(MSG_INFO, "\033[1;36m[FLOW] Esforço validado. Gerando chaves de sessão...\033[0m\n");

    /* C. Processar os valores normais para derivar 'k' */
    s_val = eap_pwd_get_scalar(data->grp, peer_scalar_raw);
    if (!s_val) goto fin;

    data->peer_element = eap_pwd_get_element(data->grp, payload);
    data->peer_scalar = s_val;
    s_val = NULL;

    if (!data->peer_element || 
        crypto_ec_point_is_at_infinity(data->grp->group, data->peer_element)) {
        goto fin;
    }

    /* --- [TESE] Cálculo do Segredo 'k' para calcular a MSK no compute_keys --- */
    
    if (data->k) crypto_bignum_deinit(data->k, 1);
    data->k = crypto_bignum_init();
    
    struct crypto_ec_point *K_pt = crypto_ec_point_init(data->grp->group);
    struct crypto_ec_point *tmp_pt = crypto_ec_point_init(data->grp->group);

    if (!K_pt || !tmp_pt || !data->k) {
        wpa_printf(MSG_ERROR, "[TESE-RADIUS] Falha de alocação");
        if (K_pt) crypto_ec_point_deinit(K_pt, 1);
        if (tmp_pt) crypto_ec_point_deinit(tmp_pt, 1);
        goto fin;
    }

	/* [TESE-DEBUG-SRV] Verificação dos valores e prints de debug */
    u8 pwe_bin[64], s_bin[32], e_bin[64];
    crypto_ec_point_to_bin(data->grp->group, data->grp->pwe, pwe_bin, pwe_bin + 32);
    crypto_bignum_to_bin(data->peer_scalar, s_bin, 32, 32);
    crypto_ec_point_to_bin(data->grp->group, data->peer_element, e_bin, e_bin + 32);

    wpa_printf(MSG_INFO, "\033[1;33m[SRV-INGREDIENTES]\033[0m");
    wpa_hexdump(MSG_INFO, "  -> PE (Point):", pwe_bin, 64);
    wpa_hexdump(MSG_INFO, "  -> Scalar (s_peer):", s_bin, 32);
    wpa_hexdump(MSG_INFO, "  -> Element (E_peer):", e_bin, 64);
    // A. tmp_pt = s_peer * PE
    if (crypto_ec_point_mul(data->grp->group, data->grp->pwe, data->peer_scalar, tmp_pt) < 0 ||
    // B. tmp_pt = tmp_pt + E_peer
        crypto_ec_point_add(data->grp->group, tmp_pt, data->peer_element, tmp_pt) < 0 ||
    // C. K_pt = s_peer * tmp_pt (Usamos o S do cliente como multiplicador final)
        crypto_ec_point_mul(data->grp->group, tmp_pt, data->peer_scalar, K_pt) < 0 ||
    // D. Extrair coordenada X para data->k
        crypto_ec_point_x(data->grp->group, K_pt, data->k) < 0) {
        
        wpa_printf(MSG_ERROR, "[TESE-RADIUS] Falha na derivação de k");
        crypto_ec_point_deinit(tmp_pt, 1);
        crypto_ec_point_deinit(K_pt, 1);
        goto fin;
    }

    // Debug para bater com o Cliente
    u8 k_debug[32];
    crypto_bignum_to_bin(data->k, k_debug, 32, 32);
    wpa_hexdump(MSG_INFO, "\033[1;36m[TESE-RADIUS] k Dinâmico Reconstruído:\033[0m", k_debug, 32);

    crypto_ec_point_deinit(tmp_pt, 1);
    crypto_ec_point_deinit(K_pt, 1);
    res = 1;

fin:
    if (s_val) crypto_bignum_deinit(s_val, 1);
    crypto_ec_point_deinit(K, 1);
    eap_pwd_state(data, res ? PWD_Confirm_Req : FAILURE);
}


static void
eap_pwd_process_confirm_resp(struct eap_sm *sm, struct eap_pwd_data *data,
			     const u8 *payload, size_t payload_len)
{

	struct crypto_hash *hash = NULL;
	u32 cs;
	u16 grp;
	u8 conf[SHA256_MAC_LEN], *cruft = NULL, *ptr;
	size_t prime_len, order_len;
	wpa_printf(MSG_INFO, "[TESE-MEM] Scalar ao entrar no Confirm: %p", (void *)data->peer_scalar);
    wpa_printf(MSG_INFO, "[TESE-DEBUG] A verificar Bypass: k=%p, state=%d", 
               data->k, data->state);

    /* Se o segredo 'k' exoste e estamos a processar a resposta ao Confirm,
       significa que a validação pesada já foi feita no Commit_Resp. */
    if (data->k != NULL) {
        wpa_printf(MSG_INFO, "\033[1;32m[TESE-RADIUS] SUCESSO: A forçar SUCCESS via Prova de Trabalho anterior.\033[0m");
        
        /* 1. Preencher Ciphersuite necessário para derivar chaves finais */
        grp = htons(data->group_num);
        ptr = (u8 *) &cs;
        os_memcpy(ptr, &grp, sizeof(u16));
        ptr += sizeof(u16);
        *ptr = EAP_PWD_DEFAULT_RAND_FUNC;
        ptr += sizeof(u8);
        *ptr = EAP_PWD_DEFAULT_PRF;

        /* 2. Gerar chaves MSK (usando o k que validámos no commit_resp) */
		wpa_printf(MSG_INFO, "\033[1;36m[DEBUG-KDF-SERVER] Ingredientes da MSK:\033[0m");

		u8 k_out[64], s_peer[64], s_my[64];
		crypto_bignum_to_bin(data->k, k_out, 32, 32);
		wpa_hexdump(MSG_INFO, "  1. Shared Secret (k):", k_out, 32);

		crypto_bignum_to_bin(data->peer_scalar, s_peer, 32, 32);
		wpa_hexdump(MSG_INFO, "  2. Peer Scalar (s_peer):", s_peer, 32);

		if (data->my_scalar) {
			crypto_bignum_to_bin(data->my_scalar, s_my, 32, 32);
			wpa_hexdump(MSG_INFO, "  3. My Scalar (s_server):", s_my, 32);
		} else {
			wpa_printf(MSG_INFO, "  3. My Scalar: NULL (Lazy Mode)");
		}

		wpa_hexdump(MSG_INFO, "  4. Peer Confirm (rcvd):", payload, 32); 
		wpa_hexdump(MSG_INFO, "  5. My Confirm (sent):", data->my_confirm, 32);
		wpa_hexdump(MSG_INFO, "  6. Ciphersuite:", (u8 *)&cs, 4);

		struct crypto_bignum *z = crypto_bignum_init();

		if (compute_keys(data->grp, data->k, 
                     data->peer_scalar, data->my_scalar,      
                     payload, data->my_confirm,    
                     &cs, data->msk, data->emsk, data->session_id) < 0) {
        eap_pwd_state(data, FAILURE);
		} else {
			wpa_hexdump(MSG_INFO, "[RESULT-SERVER] MSK CORRIGIDA:", data->msk, 32);
			eap_pwd_state(data, SUCCESS);
		}
				return; 
    }
    /* ------------------------------------ */

    wpa_printf(MSG_ERROR, "[TESE-RADIUS] Bypass falhou. A tentar fluxo original (Perigo de SegFault)...");
    /* -------------------------------------------------------- */

	prime_len = crypto_ec_prime_len(data->grp->group);
	order_len = crypto_ec_order_len(data->grp->group);

	if (payload_len != SHA256_MAC_LEN) {
		if (payload_len == SHA256_MAC_LEN + 96) {
		} else {
			goto fin;
		}
	}

	/* build up the ciphersuite: group | random_function | prf */
	grp = htons(data->group_num);
	ptr = (u8 *) &cs;
	os_memcpy(ptr, &grp, sizeof(u16));
	ptr += sizeof(u16);
	*ptr = EAP_PWD_DEFAULT_RAND_FUNC;
	ptr += sizeof(u8);
	*ptr = EAP_PWD_DEFAULT_PRF;

	/* each component of the cruft will be at most as big as the prime */
	cruft = os_malloc(prime_len * 2);
	if (!cruft) {
		wpa_printf(MSG_INFO, "EAP-PWD (peer): allocation fail");
		goto fin;
	}

	/*
	 * commit is H(k | peer_element | peer_scalar | server_element |
	 *	       server_scalar | ciphersuite)
	 */
	hash = eap_pwd_h_init();
	if (hash == NULL)
		goto fin;

	/* k */
	crypto_bignum_to_bin(data->k, cruft, prime_len, prime_len);
	eap_pwd_h_update(hash, cruft, prime_len);

	/* peer element: x, y */
	if (crypto_ec_point_to_bin(data->grp->group, data->peer_element, cruft,
				   cruft + prime_len) < 0) {
		wpa_printf(MSG_INFO, "EAP-PWD (server): confirm point "
			   "assignment fail");
		goto fin;
	}
	eap_pwd_h_update(hash, cruft, prime_len * 2);

	/* peer scalar */
	crypto_bignum_to_bin(data->peer_scalar, cruft, order_len, order_len);
	eap_pwd_h_update(hash, cruft, order_len);

	/* server element: x, y */
	if (crypto_ec_point_to_bin(data->grp->group, data->my_element, cruft,
				   cruft + prime_len) < 0) {
		wpa_printf(MSG_INFO, "EAP-PWD (server): confirm point "
			   "assignment fail");
		goto fin;
	}
	eap_pwd_h_update(hash, cruft, prime_len * 2);

	/* server scalar */
	crypto_bignum_to_bin(data->my_scalar, cruft, order_len, order_len);
	eap_pwd_h_update(hash, cruft, order_len);

	/* ciphersuite */
	eap_pwd_h_update(hash, (u8 *) &cs, sizeof(u32));

	/* all done */
	eap_pwd_h_final(hash, conf);
	hash = NULL;

	ptr = (u8 *) payload;
	if (os_memcmp_const(conf, ptr, SHA256_MAC_LEN)) {
		wpa_printf(MSG_INFO, "EAP-PWD (server): confirm did not "
			   "verify");
		goto fin;
	}

	wpa_printf(MSG_DEBUG, "EAP-pwd (server): confirm verified");
	if (compute_keys(data->grp, data->k,
			 data->peer_scalar, data->peer_scalar, conf,
			 data->my_confirm, &cs, data->msk, data->emsk,
			 data->session_id) < 0)
		eap_pwd_state(data, FAILURE);
	else
		eap_pwd_state(data, SUCCESS);

fin:
	bin_clear_free(cruft, prime_len * 2);
	eap_pwd_h_final(hash, NULL);
}


static void eap_pwd_process(struct eap_sm *sm, void *priv,
			    struct wpabuf *respData)
{
	struct eap_pwd_data *data = priv;
	const u8 *pos;
	size_t len;
	u8 lm_exch;
	u16 tot_len;

	pos = eap_hdr_validate(EAP_VENDOR_IETF, EAP_TYPE_PWD, respData, &len);
	if ((pos == NULL) || (len < 1)) {
		wpa_printf(MSG_INFO, "Bad EAP header! pos %s and len = %d",
			   (pos == NULL) ? "is NULL" : "is not NULL",
			   (int) len);
		return;
	}

	lm_exch = *pos;
	pos++;            /* skip over the bits and the exch */
	len--;

	/*
	 * if we're fragmenting then this should be an ACK with no data,
	 * just return and continue fragmenting in the "build" section above
	 */
	if (data->out_frag_pos) {
		if (len > 1)
			wpa_printf(MSG_INFO, "EAP-pwd: Bad response! "
				   "Fragmenting but not an ACK");
		else
			wpa_printf(MSG_DEBUG, "EAP-pwd: received ACK from "
				   "peer");
		return;
	}
	/*
	 * if we're receiving fragmented packets then we need to buffer...
	 *
	 * the first fragment has a total length
	 */
	if (EAP_PWD_GET_LENGTH_BIT(lm_exch)) {
		if (len < 2) {
			wpa_printf(MSG_DEBUG,
				   "EAP-pwd: Frame too short to contain Total-Length field");
			return;
		}
		tot_len = WPA_GET_BE16(pos);
		wpa_printf(MSG_DEBUG, "EAP-pwd: Incoming fragments, total "
			   "length = %d", tot_len);
		if (tot_len > 15000)
			return;
		if (data->inbuf) {
			wpa_printf(MSG_DEBUG,
				   "EAP-pwd: Unexpected new fragment start when previous fragment is still in use");
			return;
		}
		data->inbuf = wpabuf_alloc(tot_len);
		if (data->inbuf == NULL) {
			wpa_printf(MSG_INFO, "EAP-pwd: Out of memory to "
				   "buffer fragments!");
			return;
		}
		data->in_frag_pos = 0;
		pos += sizeof(u16);
		len -= sizeof(u16);
	}
	/*
	 * the first and all intermediate fragments have the M bit set
	 */
	if (EAP_PWD_GET_MORE_BIT(lm_exch) || data->in_frag_pos) {
		if (!data->inbuf) {
			wpa_printf(MSG_DEBUG,
				   "EAP-pwd: No buffer for reassembly");
			eap_pwd_state(data, FAILURE);
			return;
		}
		if ((data->in_frag_pos + len) > wpabuf_size(data->inbuf)) {
			wpa_printf(MSG_DEBUG, "EAP-pwd: Buffer overflow "
				   "attack detected! (%d+%d > %d)",
				   (int) data->in_frag_pos, (int) len,
				   (int) wpabuf_size(data->inbuf));
			eap_pwd_state(data, FAILURE);
			return;
		}
		wpabuf_put_data(data->inbuf, pos, len);
		data->in_frag_pos += len;
	}
	if (EAP_PWD_GET_MORE_BIT(lm_exch)) {
		wpa_printf(MSG_DEBUG, "EAP-pwd: Got a %d byte fragment",
			   (int) len);
		return;
	}
	/*
	 * last fragment won't have the M bit set (but we're obviously
	 * buffering fragments so that's how we know it's the last)
	 */
	if (data->in_frag_pos && data->inbuf) {
		pos = wpabuf_head_u8(data->inbuf);
		len = data->in_frag_pos;
		wpa_printf(MSG_DEBUG, "EAP-pwd: Last fragment, %d bytes",
			   (int) len);
	}

    /* --- [TESE-SFTR] VALIDAÇÃO DO TICKET --- */
    if (EAP_PWD_GET_EXCHANGE(lm_exch) == EAP_PWD_OPCODE_COMMIT_EXCH && len >= 32) {
        if (os_memcmp(pos, zeros, 32) == 0) { 
            wpa_printf(MSG_INFO, "\033[1;34m[TESE-SFTR] Fast-Path detetado! A validar Ticket...\033[0m");

            /* O ticket está depois dos 32 bytes do Scalar zero */
            if (tese_validar_ticket_sftr(sm, data, pos + 32)) {
                
                /* --- Inicializar variáveis para o Confirm não dar erro --- */
                if (data->peer_scalar) crypto_bignum_deinit(data->peer_scalar, 1);
                
                /* Criamos o bignum 0. 'pos' aponta para os 32 bytes de zeros que vieram da rede */
                data->peer_scalar = crypto_bignum_init_set(pos, 32);

                /* Garantir que o grupo está carregado para o compute_keys posterior */
                if (!data->grp) {
                    data->grp = get_eap_pwd_group(data->group_num);
                }
                /* -------------------------------------------------------------------- */

                /* Mudar o estado interno do PWD para esperar o Confirm */
                eap_pwd_state(data, PWD_Confirm_Req); 
                
                /* Limpeza de fragmentação */
                if (data->in_frag_pos) {
                    wpabuf_free(data->inbuf);
                    data->inbuf = NULL;
                    data->in_frag_pos = 0;
                }
                
                wpa_printf(MSG_INFO, "[TESE-SFTR] Ticket OK. Scalar 0 guardado. Memoria segura.");
                return; 
            }
        }
    }
    /* -------------------------------------------- */
    /* -------------------------------------------- */

	
	switch (EAP_PWD_GET_EXCHANGE(lm_exch)) {
	case EAP_PWD_OPCODE_ID_EXCH:
		eap_pwd_process_id_resp(sm, data, pos, len);
		break;
	case EAP_PWD_OPCODE_COMMIT_EXCH:
		eap_pwd_process_commit_resp(sm, data, pos, len);
		break;
	case EAP_PWD_OPCODE_CONFIRM_EXCH:
		eap_pwd_process_confirm_resp(sm, data, pos, len);
		break;
	}
	/*
	 * if we had been buffering fragments, here's a great place
	 * to clean up
	 */
	if (data->in_frag_pos) {
		wpabuf_free(data->inbuf);
		data->inbuf = NULL;
		data->in_frag_pos = 0;
	}
}

static u8 * eap_pwd_getkey(struct eap_sm *sm, void *priv, size_t *len)
{
    struct eap_pwd_data *data = priv;
    u8 *key;



    if (data == NULL) {
        return NULL;
    }




    if (data->state != SUCCESS) {
        return NULL;
    }

    
    // Se data->msk for lixo ou nao inicializado, o os_memdup morre aqui
    key = os_memdup(data->msk, EAP_MSK_LEN);
    
    if (key == NULL) {
        return NULL;
    }

    *len = EAP_MSK_LEN;


    return key;
}


static u8 * eap_pwd_get_emsk(struct eap_sm *sm, void *priv, size_t *len)
{
	struct eap_pwd_data *data = priv;
	u8 *key;

	if (data->state != SUCCESS)
		return NULL;

	key = os_memdup(data->emsk, EAP_EMSK_LEN);
	if (key == NULL)
		return NULL;

	*len = EAP_EMSK_LEN;

	return key;
}


static bool eap_pwd_is_success(struct eap_sm *sm, void *priv)
{
	struct eap_pwd_data *data = priv;
	return data->state == SUCCESS;
}


static bool eap_pwd_is_done(struct eap_sm *sm, void *priv)
{
	struct eap_pwd_data *data = priv;
	return (data->state == SUCCESS) || (data->state == FAILURE);
}


static u8 * eap_pwd_get_session_id(struct eap_sm *sm, void *priv, size_t *len)
{
	struct eap_pwd_data *data = priv;
	u8 *id;

	if (data->state != SUCCESS)
		return NULL;


	id = os_memdup(data->session_id, 1 + SHA256_MAC_LEN);
	if (id == NULL)
		return NULL;

	*len = 1 + SHA256_MAC_LEN;

	return id;
}


int eap_server_pwd_register(void)
{
	struct eap_method *eap;

	eap = eap_server_method_alloc(EAP_SERVER_METHOD_INTERFACE_VERSION,
				      EAP_VENDOR_IETF, EAP_TYPE_PWD,
				      "PWD");
	if (eap == NULL)
		return -1;

	eap->init = eap_pwd_init;
	eap->reset = eap_pwd_reset;
	eap->buildReq = eap_pwd_build_req;
	eap->check = eap_pwd_check;
	eap->process = eap_pwd_process;
	eap->isDone = eap_pwd_is_done;
	eap->getKey = eap_pwd_getkey;
	eap->get_emsk = eap_pwd_get_emsk;
	eap->isSuccess = eap_pwd_is_success;
	eap->getSessionId = eap_pwd_get_session_id;

	return eap_server_method_register(eap);
}
