#define name0(__str__) __str__.substr(0, __str__.length() - 9)
#define name3(__str__) __str__.substr(0, __str__.length() - 6)
#define name9(__str__) __str__
#define skip_space(__str__) __str__.substr(__str__.find(' ') + 1)

/*
 * HACK: wrapping std::min in parens to get around a collision with
 * windows macro definition of min. :/
 */
#define skip_space_or_eos(__str__) \
    (std::min)(__str__.find(' '), __str__.length() - 1) + 1

#define chan_name(__idx__) \
    m_nuggit_config.chat_server().channelnames().at(__idx__)
#define chan_ip() resolve_external_ip()
#define chan_port() m_nuggit_config.nuggit().tcp_port()
#define chan_hash() get_channel_hash(chan_ip(), chan_port())
