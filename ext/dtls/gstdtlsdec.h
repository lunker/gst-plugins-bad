/*
 * Copyright (c) 2014, Ericsson AB. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this
 * list of conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 */

#ifndef gstdtlsdec_h
#define gstdtlsdec_h

#include "gstdtlsagent.h"
#include "gstdtlsconnection.h"

#include <gst/gst.h>

G_BEGIN_DECLS

#define GST_TYPE_DTLS_DEC \
    (gst_dtls_dec_get_type())
#define GST_DTLS_DEC(obj) \
    (G_TYPE_CHECK_INSTANCE_CAST((obj), GST_TYPE_DTLS_DEC, GstDtlsDec))
#define GST_DTLS_DEC_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_CAST((klass), GST_TYPE_DTLS_DEC, GstDtlsDecClass))
#define GST_IS_DTLS_DEC(obj) \
    (G_TYPE_CHECK_INSTANCE_TYPE((obj), GST_TYPE_DTLS_DEC))
#define GST_IS_DTLS_DEC_CLASS(klass) \
    (G_TYPE_CHECK_CLASS_TYPE((klass), GST_TYPE_DTLS_DEC))

typedef struct _GstDtlsDec GstDtlsDec;
typedef struct _GstDtlsDecClass GstDtlsDecClass;

struct _GstDtlsDec {
    GstElement element;

    GstPad *src;
    GstPad *sink;
    GMutex src_mutex;

    GstDtlsAgent *agent;
    GstDtlsConnection *connection;
    GMutex connection_mutex;
    gchar *connection_id;
    gchar *peer_pem;

    GstBuffer *decoder_key;
    guint srtp_cipher;
    guint srtp_auth;
};

struct _GstDtlsDecClass {
    GstElementClass parent_class;
		void (* invoke_on_key_received) (GstDtlsDec * self, guint cipher, guint auth);
		void (* invoke_on_peer_certificate_received) (GstDtlsDec * self, gchar *peer_pem);
};

GType gst_dtls_dec_get_type(void);

gboolean gst_dtls_dec_plugin_init(GstPlugin *);

GstDtlsConnection *gst_dtls_dec_fetch_connection(gchar *id);

G_END_DECLS

#endif /* gstdtlsdec_h */
