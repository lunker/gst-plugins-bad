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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "gstdtlssrtpenc.h"
#include "gstdtlsconnection.h"

#include <stdio.h>
// #include "../srtp/gstsrtp-enumtypes.h"
// #include "../srtp/gstsrtp.h"

static GstStaticPadTemplate rtp_sink_template =
    GST_STATIC_PAD_TEMPLATE ("rtp_sink_%d",
    GST_PAD_SINK,
    GST_PAD_REQUEST,
    GST_STATIC_CAPS ("application/x-rtp;application/x-rtcp")
    );

static GstStaticPadTemplate rtcp_sink_template =
    GST_STATIC_PAD_TEMPLATE ("rtcp_sink_%d",
    GST_PAD_SINK,
    GST_PAD_REQUEST,
    GST_STATIC_CAPS ("application/x-rtp;application/x-rtcp")
    );

static GstStaticPadTemplate data_sink_template =
GST_STATIC_PAD_TEMPLATE ("data_sink",
    GST_PAD_SINK,
    GST_PAD_REQUEST,
    GST_STATIC_CAPS_ANY);

static GstStaticPadTemplate src_template = GST_STATIC_PAD_TEMPLATE ("src",
    GST_PAD_SRC,
    GST_PAD_ALWAYS,
    GST_STATIC_CAPS_ANY);

GST_DEBUG_CATEGORY_STATIC (gst_dtls_srtp_enc_debug);
#define GST_CAT_DEFAULT gst_dtls_srtp_enc_debug

#define gst_dtls_srtp_enc_parent_class parent_class
G_DEFINE_TYPE_WITH_CODE (GstDtlsSrtpEnc, gst_dtls_srtp_enc,
    GST_TYPE_DTLS_SRTP_BIN, GST_DEBUG_CATEGORY_INIT (gst_dtls_srtp_enc_debug,
        "dtlssrtpenc", 0, "DTLS Decoder"));

#define DEFAULT_DTLS_KEY NULL
#define DEFAULT_RTP_CIPHER      GST_SRTP_CIPHER_AES_128_ICM
#define DEFAULT_RTP_AUTH        GST_SRTP_AUTH_HMAC_SHA1_80
#define DEFAULT_RTCP_CIPHER     DEFAULT_RTP_CIPHER
#define DEFAULT_RTCP_AUTH       DEFAULT_RTP_AUTH
#define DEFAULT_SRTP_CIPHER 0
#define DEFAULT_SRTP_AUTH 0

enum
{
  SIGNAL_ON_KEY_SET,
	SIGNAL_ON_HANDSHAKE_COMPLETE,
	SIGNAL_ON_SAVE_DTLS_ENC_INFO,
	SIGNAL_INVOKE_ON_KEY_RECEIVED,
  NUM_SIGNALS
};

static guint signals[NUM_SIGNALS];

enum
{
  PROP_0,
  PROP_IS_CLIENT,
	PROP_DTLS_KEY,
	PROP_ENCODER_KEY,
	PROP_SRTP_AUTH,
	PROP_SRTP_CIPHER,
//	PROP_RTP_CIPHER,
//	PROP_RTP_AUTH,
  NUM_PROPERTIES
};

static GParamSpec *properties[NUM_PROPERTIES];

#define DEFAULT_IS_CLIENT FALSE

static gboolean transform_enum (GBinding *, const GValue * source_value,
    GValue * target_value, GEnumClass *);

static void gst_dtls_srtp_enc_set_property (GObject *, guint prop_id,
    const GValue *, GParamSpec *);
static void gst_dtls_srtp_enc_get_property (GObject *, guint prop_id,
    GValue *, GParamSpec *);

static GstPad *add_ghost_pad (GstElement *, const gchar * name, GstPad *,
    GstPadTemplate *);
static GstPad *gst_dtls_srtp_enc_request_new_pad (GstElement *,
    GstPadTemplate *, const gchar * name, const GstCaps *);

static void on_key_received (GObject * encoder, GstDtlsSrtpEnc *);
static void on_save_dtls_enc_info (GObject * encoder, GstStructure *enc_info,  GstDtlsSrtpEnc * self);


static void gst_dtls_srtp_enc_remove_dtls_element (GstDtlsSrtpBin *);
static GstPadProbeReturn remove_dtls_encoder_probe_callback (GstPad *,
    GstPadProbeInfo *, GstElement *);

static gchar*
gst_dtls_srtp_enc_on_handshake_complete (GstDtlsSrtpEnc * self, gchar* key)
{
	GST_WARNING ("### wow !!!! ");
	return key;
}

static void 
gst_dtls_srtp_enc_invoke_on_key_received (GstDtlsSrtpEnc * self)
{
//	GST_DTLS_SRTP_ENC
	GST_DEBUG ("### forcely invoke 'on-key-received' ");

	// fucking logic 
	//force_on_key_received ( (GObject *) self->bin.dtls_element, self);
	g_signal_emit_by_name ( (GObject *) self->bin.dtls_element, "invoke-on-key-received");

}


static void
gst_dtls_srtp_enc_class_init (GstDtlsSrtpEncClass * klass)
{
  GObjectClass *gobject_class;
  GstElementClass *element_class;
  GstDtlsSrtpBinClass *dtls_srtp_bin_class;

  gobject_class = (GObjectClass *) klass;
  element_class = (GstElementClass *) klass;
  dtls_srtp_bin_class = (GstDtlsSrtpBinClass *) klass;

  gobject_class->set_property =
      GST_DEBUG_FUNCPTR (gst_dtls_srtp_enc_set_property);
  gobject_class->get_property =
      GST_DEBUG_FUNCPTR (gst_dtls_srtp_enc_get_property);

  element_class->request_new_pad =
      GST_DEBUG_FUNCPTR (gst_dtls_srtp_enc_request_new_pad);

  dtls_srtp_bin_class->remove_dtls_element =
      GST_DEBUG_FUNCPTR (gst_dtls_srtp_enc_remove_dtls_element);

  signals[SIGNAL_ON_KEY_SET] =
      g_signal_new ("on-key-set", G_TYPE_FROM_CLASS (klass),
      G_SIGNAL_RUN_LAST, 0, NULL, NULL,
      g_cclosure_marshal_generic, G_TYPE_NONE, 0);

	signals[SIGNAL_ON_HANDSHAKE_COMPLETE] =
      g_signal_new ("on-handshake-complete", G_TYPE_FROM_CLASS (klass),
      G_SIGNAL_RUN_LAST, 
			G_STRUCT_OFFSET (GstDtlsSrtpEncClass, on_handshake_complete),
			 NULL, NULL, g_cclosure_marshal_generic, G_TYPE_NONE, 1, G_TYPE_STRING);

  signals[SIGNAL_ON_SAVE_DTLS_ENC_INFO] = 
      g_signal_new ("on-save-dtls-enc-info", G_TYPE_FROM_CLASS (klass),
      G_SIGNAL_RUN_LAST, 0, NULL, NULL,
      g_cclosure_marshal_generic, G_TYPE_NONE, 1, GST_TYPE_STRUCTURE);

  signals[SIGNAL_INVOKE_ON_KEY_RECEIVED] =
      g_signal_new ("invoke-on-key-received", G_TYPE_FROM_CLASS (klass),
      G_SIGNAL_RUN_LAST, 
			G_STRUCT_OFFSET (GstDtlsSrtpEncClass, invoke_on_key_received), 
			NULL, NULL,
      g_cclosure_marshal_generic, G_TYPE_NONE, 0);

/*
  properties[PROP_IS_CLIENT] =
      g_param_spec_boolean ("is-client",
      "Is client",
      "Set to true if the decoder should act as "
      "client and initiate the handshake",
      DEFAULT_IS_CLIENT,
      GST_PARAM_MUTABLE_READY | G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS);
*/

	 g_object_class_install_property (gobject_class, PROP_IS_CLIENT,
      g_param_spec_boolean ("is-client", 
          "prop dtls key ",
          "The transport used to send and receive RTP and RTCP packets.",
          DEFAULT_IS_CLIENT,
          GST_PARAM_MUTABLE_READY | G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

	 g_object_class_install_property (gobject_class, PROP_DTLS_KEY,
      g_param_spec_boxed ("key", 
          "prop dtls key ",
          "The transport used to send and receive RTP and RTCP packets.",
          GST_TYPE_BUFFER,
          G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));


	 g_object_class_install_property (gobject_class, PROP_ENCODER_KEY,
      g_param_spec_boxed ("encoder-key", 
          "prop dtls key ",
          "The transport used to send and receive RTP and RTCP packets.",
          GST_TYPE_BUFFER,
          G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

	 g_object_class_install_property (gobject_class, PROP_SRTP_CIPHER,
     g_param_spec_uint ("srtp-cipher",
      "SRTP cipher",
      "The SRTP cipher selected in the DTLS handshake. "
      "The value will be set to an GstDtlsSrtpCipher.",
      0, GST_DTLS_SRTP_CIPHER_AES_128_ICM, DEFAULT_SRTP_CIPHER,
      G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

	 g_object_class_install_property (gobject_class, PROP_SRTP_AUTH,
      g_param_spec_uint ("srtp-auth",
      "SRTP authentication",
      "The SRTP authentication selected in the DTLS handshake. "
      "The value will be set to an GstDtlsSrtpAuth.",
      0, GST_DTLS_SRTP_AUTH_HMAC_SHA1_80, DEFAULT_SRTP_AUTH,
      G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));


	klass->on_handshake_complete = gst_dtls_srtp_enc_on_handshake_complete;
	klass->invoke_on_key_received = gst_dtls_srtp_enc_invoke_on_key_received;

//  g_object_class_install_properties (gobject_class, NUM_PROPERTIES, properties);

  gst_element_class_add_pad_template (element_class,
      gst_static_pad_template_get (&rtp_sink_template));
  gst_element_class_add_pad_template (element_class,
      gst_static_pad_template_get (&rtcp_sink_template));
  gst_element_class_add_pad_template (element_class,
      gst_static_pad_template_get (&data_sink_template));
  gst_element_class_add_pad_template (element_class,
      gst_static_pad_template_get (&src_template));

  gst_element_class_set_static_metadata (element_class,
      "DTLS-SRTP Encoder",
      "Encoder/Network/DTLS/SRTP",
      "Encodes SRTP packets with a key received from DTLS",
      "Patrik Oldsberg patrik.oldsberg@ericsson.com");
}

static void
gst_dtls_srtp_enc_init (GstDtlsSrtpEnc * self)
{
  GstElementClass *klass = GST_ELEMENT_GET_CLASS (GST_ELEMENT (self));
  static GEnumClass *cipher_enum_class, *auth_enum_class;
  gboolean ret;

/*
                 +--------------------+     +-----------------+
     rtp_sink-R-o|rtp_sink     rtp_src|o-R-o|                 |
                 |       srtpenc      |     |                 |
    rtcp_sink-R-o|srtcp_sink  rtcp_src|o-R-o|                 |
                 +--------------------+     |     funnel      |o---src
                                            |                 |
                 +--------------------+     |                 |
    data_sink-R-o|       dtlsenc      |o---o|                 |
                 +--------------------+     +-----------------+
*/

  self->srtp_enc = gst_element_factory_make ("srtpenc", "srtp-encoder");
  if (!self->srtp_enc) {
    GST_ERROR_OBJECT (self,
        "failed to create srtp encoder, is the srtp plugin registered?");
    return;
  }
  g_return_if_fail (self->srtp_enc);
  self->bin.dtls_element = gst_element_factory_make ("dtlsenc", "dtls-encoder");
  if (!self->bin.dtls_element) {
    GST_ERROR_OBJECT (self, "failed to create dtls encoder");
    return;
  }
  self->funnel = gst_element_factory_make ("funnel", "funnel");
  if (!self->funnel) {
    GST_ERROR_OBJECT (self, "failed to create funnel");
    return;
  }

  gst_bin_add_many (GST_BIN (self), self->bin.dtls_element, self->srtp_enc,
      self->funnel, NULL);

  ret = gst_element_link (self->bin.dtls_element, self->funnel);
  g_return_if_fail (ret);

  add_ghost_pad (GST_ELEMENT (self), "src",
      gst_element_get_static_pad (self->funnel, "src"),
      gst_element_class_get_pad_template (klass, "src"));

  g_signal_connect (self->bin.dtls_element, "on-key-received",
      G_CALLBACK (on_key_received), self);

	/* lunker:: add for handling signal 'on-save-dtls-enc-info' */
	g_signal_connect (self->bin.dtls_element, "on-save-dtls-enc-info", G_CALLBACK (on_save_dtls_enc_info), self);
	g_object_bind_property (self, "encoder-key", self->bin.dtls_element, "encoder-key", G_BINDING_DEFAULT);
	g_object_bind_property (self, "srtp-auth", self->bin.dtls_element, "srtp-auth", G_BINDING_DEFAULT);
	g_object_bind_property (self, "srtp-cipher", self->bin.dtls_element, "srtp-cipher", G_BINDING_DEFAULT);
	

  if (g_once_init_enter (&cipher_enum_class)) {
    GType type = g_type_from_name ("GstSrtpCipherType");
    g_assert (type);
    g_once_init_leave (&cipher_enum_class, g_type_class_peek (type));
  }
  if (g_once_init_enter (&auth_enum_class)) {
    GType type = g_type_from_name ("GstSrtpAuthType");
    g_assert (type);
    g_once_init_leave (&auth_enum_class, g_type_class_peek (type));
  }

  g_object_set (self->srtp_enc, "random-key", TRUE, NULL);

	/* lunker:: bind prop for session clustering */
  g_object_bind_property (G_OBJECT (self), "key", self->srtp_enc, "key",
      G_BINDING_DEFAULT);

/*

  g_object_bind_property (G_OBJECT (self), "rtp-cipher", self->srtp_enc, "rtp-cipher",
      G_BINDING_DEFAULT);
  g_object_bind_property (G_OBJECT (self), "rtp-auth", self->srtp_enc, "rtp-auth",
      G_BINDING_DEFAULT);

  g_object_bind_property (G_OBJECT (self), "rtp-cipher", self->srtp_enc, "rtcp-cipher",
      G_BINDING_DEFAULT);
  g_object_bind_property (G_OBJECT (self), "rtp-auth", self->srtp_enc, "rtcp-auth",
      G_BINDING_DEFAULT);
*/

  g_object_bind_property_full (G_OBJECT (self), "srtp-cipher", self->srtp_enc,
      "rtp-cipher", G_BINDING_DEFAULT, (GBindingTransformFunc) transform_enum,
      NULL, cipher_enum_class, NULL);
  g_object_bind_property_full (G_OBJECT (self), "srtcp-cipher", self->srtp_enc,
      "rtcp-cipher", G_BINDING_DEFAULT, (GBindingTransformFunc) transform_enum,
      NULL, cipher_enum_class, NULL);
  g_object_bind_property_full (G_OBJECT (self), "srtp-auth", self->srtp_enc,
      "rtp-auth", G_BINDING_DEFAULT, (GBindingTransformFunc) transform_enum,
      NULL, auth_enum_class, NULL);
  g_object_bind_property_full (G_OBJECT (self), "srtcp-auth", self->srtp_enc,
      "rtcp-auth", G_BINDING_DEFAULT, (GBindingTransformFunc) transform_enum,
      NULL, auth_enum_class, NULL);

	g_object_set (self->srtp_enc, "key", NULL, NULL);

}

static gboolean
transform_enum (GBinding * binding, const GValue * source_value,
    GValue * target_value, GEnumClass * enum_class)
{
  GEnumValue *enum_value;
  const gchar *nick;

  nick = g_value_get_string (source_value);
  g_return_val_if_fail (nick, FALSE);

  enum_value = g_enum_get_value_by_nick (enum_class, nick);
  g_return_val_if_fail (enum_value, FALSE);

  GST_DEBUG_OBJECT (g_binding_get_source (binding),
      "transforming enum from %s to %d", nick, enum_value->value);

  g_value_set_enum (target_value, enum_value->value);

  return TRUE;
}

static void
gst_dtls_srtp_enc_set_property (GObject * object,
    guint prop_id, const GValue * value, GParamSpec * pspec)
{
  GstDtlsSrtpEnc *self = GST_DTLS_SRTP_ENC (object);

  switch (prop_id) {
    case PROP_IS_CLIENT:
      if (self->bin.dtls_element) {
        g_object_set_property (G_OBJECT (self->bin.dtls_element), "is-client",
            value);
      } else {
        GST_WARNING_OBJECT (self,
            "tried to set is-client after disabling DTLS");
      }
      break;
		case PROP_ENCODER_KEY:
			if (self->encoder_key)
				gst_buffer_unref (self->encoder_key);
			self->encoder_key = g_value_dup_boxed (value);
			GST_DEBUG ("### set prop 'encoder-key' with value '[%p]'", self->encoder_key);
			// GST_DEBUG ("### set prop 'encoder-key' with value '[%s]'",  g_base64_encode (self->encoder_key,30) );
			break;
		case PROP_DTLS_KEY:
			if( self->dtls_key) 
				gst_buffer_unref (self->dtls_key);
			self->dtls_key = g_value_dup_boxed (value);
			GST_DEBUG ("### set prop 'dtls-key' with value '[%p]'", self->dtls_key);
			break;
		case PROP_SRTP_CIPHER:
			self->srtp_cipher = g_value_get_uint (value);
			GST_DEBUG ("### set prop 'srtp-cipher' with value '[%d]'", self->srtp_cipher);
			break;
		case PROP_SRTP_AUTH:
			self->srtp_auth = g_value_get_uint (value);
			GST_DEBUG ("### set prop 'srtp-auth' with value '[%d]'", self->srtp_auth);		
			break;
/*
		case PROP_RTP_CIPHER:
      self->rtp_cipher = g_value_get_enum (value);
      GST_INFO_OBJECT (object, "Set property: rtp cipher=%d",
          self->rtp_cipher);
      break;
		case PROP_RTP_AUTH:
      self->rtp_auth = g_value_get_enum (value);
      GST_INFO_OBJECT (object, "Set property: rtp auth=%d", self->rtp_auth);
      break;
*/

    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (self, prop_id, pspec);
  }
}

static void
gst_dtls_srtp_enc_get_property (GObject * object,
    guint prop_id, GValue * value, GParamSpec * pspec)
{
  GstDtlsSrtpEnc *self = GST_DTLS_SRTP_ENC (object);

  switch (prop_id) {
    case PROP_IS_CLIENT:
      if (self->bin.dtls_element) {
        g_object_get_property (G_OBJECT (self->bin.dtls_element), "is-client",
            value);
      } else {
        GST_WARNING_OBJECT (self,
            "tried to get is-client after disabling DTLS");
      }
      break;
		case PROP_DTLS_KEY:
			if(self->dtls_key)
				g_value_set_boxed (value, self->dtls_key);
			break;
		case PROP_ENCODER_KEY:
				g_value_set_boxed (value, self->encoder_key);
			break;
		case PROP_SRTP_AUTH:
			g_value_set_uint (value, self->srtp_auth);
			break;
		case PROP_SRTP_CIPHER:
			g_value_set_uint (value, self->srtp_cipher);
			break;
/*
		case PROP_RTP_CIPHER:
      g_value_set_enum (value, self->rtp_cipher);
      break;
    case PROP_RTP_AUTH:
      g_value_set_enum (value, self->rtp_auth);
      break;
*/
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (self, prop_id, pspec);
  }
}

static GstPad *
add_ghost_pad (GstElement * element,
    const gchar * name, GstPad * target, GstPadTemplate * templ)
{
  GstPad *pad;
  gboolean ret;

  pad = gst_ghost_pad_new_from_template (name, target, templ);
  gst_object_unref (target);
  target = NULL;

  ret = gst_pad_set_active (pad, TRUE);
  g_warn_if_fail (ret);

  ret = gst_element_add_pad (element, pad);
  g_warn_if_fail (ret);

  return pad;
}

static GstPad *
gst_dtls_srtp_enc_request_new_pad (GstElement * element,
    GstPadTemplate * templ, const gchar * name, const GstCaps * caps)
{
  GstDtlsSrtpEnc *self = GST_DTLS_SRTP_ENC (element);
  GstElementClass *klass = GST_ELEMENT_GET_CLASS (element);
  GstPad *target_pad;
  GstPad *ghost_pad = NULL;
  guint pad_n;
  gchar *srtp_src_name;

  GST_DEBUG_OBJECT (element, "pad requested");

  g_return_val_if_fail (templ->direction == GST_PAD_SINK, NULL);
  g_return_val_if_fail (self->srtp_enc, NULL);

  if (templ == gst_element_class_get_pad_template (klass, "rtp_sink_%d")) {
    target_pad = gst_element_get_request_pad (self->srtp_enc, name);
    g_return_val_if_fail (target_pad, NULL);

    sscanf (GST_PAD_NAME (target_pad), "rtp_sink_%d", &pad_n);
    srtp_src_name = g_strdup_printf ("rtp_src_%d", pad_n);

    gst_element_link_pads (self->srtp_enc, srtp_src_name, self->funnel, NULL);

    g_free (srtp_src_name);

    ghost_pad = add_ghost_pad (element, name, target_pad, templ);

    GST_LOG_OBJECT (self, "added rtp sink pad");
  } else if (templ == gst_element_class_get_pad_template (klass,
          "rtcp_sink_%d")) {
    target_pad = gst_element_get_request_pad (self->srtp_enc, name);
    g_return_val_if_fail (target_pad, NULL);

    sscanf (GST_PAD_NAME (target_pad), "rtcp_sink_%d", &pad_n);
    srtp_src_name = g_strdup_printf ("rtcp_src_%d", pad_n);

    gst_element_link_pads (self->srtp_enc, srtp_src_name, self->funnel, NULL);

    g_free (srtp_src_name);

    ghost_pad = add_ghost_pad (element, name, target_pad, templ);

    GST_LOG_OBJECT (self, "added rtcp sink pad");
  } else if (templ == gst_element_class_get_pad_template (klass, "data_sink")) {
    g_return_val_if_fail (self->bin.dtls_element, NULL);
    target_pad = gst_element_get_request_pad (self->bin.dtls_element, "sink");

    ghost_pad = add_ghost_pad (element, name, target_pad, templ);

    GST_LOG_OBJECT (self, "added data sink pad");
  } else {
    g_warn_if_reached ();
  }

  if (caps && ghost_pad) {
    g_object_set (ghost_pad, "caps", caps, NULL);
  }

  return ghost_pad;
}

static void
on_key_received (GObject * encoder, GstDtlsSrtpEnc * self)
{
  GstDtlsSrtpBin *bin = GST_DTLS_SRTP_BIN (self);
  GstBuffer *buffer = NULL;
  guint cipher, auth;
	gchar * key_str=NULL;

	GST_DEBUG ("### handler for signal 'on-key-received' from gstdtlsenc");

  if (!(bin->key_is_set || bin->srtp_cipher || bin->srtp_auth
          || bin->srtcp_cipher || bin->srtcp_auth)) {
    g_object_get (encoder,
        "encoder-key", &buffer,
        "srtp-cipher", &cipher, "srtp-auth", &auth, NULL);

		GST_DEBUG ("### get prop 'srtp-cipher' with value '%d'", cipher);
		GST_DEBUG ("### get prop 'srtp-auth' with value '%d'", auth);

    g_object_set (self->srtp_enc,
        "rtp-cipher", cipher,
        "rtcp-cipher", cipher,
        "rtp-auth", auth,
        "rtcp-auth", auth, "key", buffer, "random-key", FALSE, NULL);

    gst_buffer_unref (buffer);
	
		// set length hardcode for test 
		key_str = g_base64_encode (buffer, 30); 
		GST_WARNING ("### dtls-master-key : '%s'", key_str);

    g_signal_emit (self, signals[SIGNAL_ON_KEY_SET], 0);
		g_signal_emit (self, signals[SIGNAL_ON_HANDSHAKE_COMPLETE], 0,g_strdup (key_str), TRUE );
  } else {
    GST_DEBUG_OBJECT (self,
        "ignoring keys received from DTLS handshake, key struct is set");
  }
}

static void 
on_save_dtls_enc_info (GObject * encoder, GstStructure *enc_info,  GstDtlsSrtpEnc * self)
{
	GST_WARNING ("###  signal 'on-save-dtls-enc-info'");
	
	g_signal_emit (self, signals[SIGNAL_ON_SAVE_DTLS_ENC_INFO], 0, enc_info);
}

static void
gst_dtls_srtp_enc_remove_dtls_element (GstDtlsSrtpBin * bin)
{
  GstDtlsSrtpEnc *self = GST_DTLS_SRTP_ENC (bin);
  GstPad *dtls_sink_pad, *peer_pad;
  gulong id;
  guint rtp_cipher = 1, rtcp_cipher = 1, rtp_auth = 1, rtcp_auth = 1;

  if (!bin->dtls_element) {
    return;
  }

  g_object_get (self->srtp_enc,
      "rtp-cipher", &rtp_cipher,
      "rtcp-cipher", &rtcp_cipher,
      "rtp-auth", &rtp_auth, "rtcp-auth", &rtcp_auth, NULL);

  if (!rtp_cipher && !rtcp_cipher && !rtp_auth && !rtcp_auth) {
    g_object_set (self->srtp_enc, "random-key", FALSE, NULL);
  }

  dtls_sink_pad = gst_element_get_static_pad (bin->dtls_element, "sink");

  if (!dtls_sink_pad) {
    gst_element_set_state (GST_ELEMENT (bin->dtls_element), GST_STATE_NULL);
    gst_bin_remove (GST_BIN (self), bin->dtls_element);
    bin->dtls_element = NULL;
    return;
  }

  peer_pad = gst_pad_get_peer (dtls_sink_pad);
  g_return_if_fail (peer_pad);
  gst_object_unref (dtls_sink_pad);
  dtls_sink_pad = NULL;

  id = gst_pad_add_probe (peer_pad, GST_PAD_PROBE_TYPE_BLOCK_DOWNSTREAM,
      (GstPadProbeCallback) remove_dtls_encoder_probe_callback,
      bin->dtls_element, NULL);
  g_return_if_fail (id);
  bin->dtls_element = NULL;

  gst_pad_push_event (peer_pad,
      gst_event_new_custom (GST_EVENT_CUSTOM_DOWNSTREAM,
          gst_structure_new_empty ("dummy")));

  gst_object_unref (peer_pad);
}

static GstPadProbeReturn
remove_dtls_encoder_probe_callback (GstPad * pad,
    GstPadProbeInfo * info, GstElement * element)
{
  gst_pad_remove_probe (pad, GST_PAD_PROBE_INFO_ID (info));

  gst_element_set_state (GST_ELEMENT (element), GST_STATE_NULL);
  gst_bin_remove (GST_BIN (GST_ELEMENT_PARENT (element)), element);

  return GST_PAD_PROBE_OK;
}
