#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/un.h>
#include <sys/socket.h>
#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif

#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <stdarg.h>
#ifdef HAVE_STDINT_H
# include <stdint.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include "openbsd-compat/sys-queue.h"
#include "sshbuf.h"
#include "packet.h"
#include "channels.h"
#include "sshkey.h"

typedef void chan_fn(struct ssh *, Channel *c,
    fd_set *readset, fd_set *writeset);

struct permission_set {
	/*
	 * List of all local permitted host/port pairs to allow for the
	 * user.
	 */
	u_int num_permitted_user;
	struct permission *permitted_user;

	/*
	 * List of all permitted host/port pairs to allow for the admin.
	 */
	u_int num_permitted_admin;
	struct permission *permitted_admin;

	/*
	 * If this is true, all opens/listens are permitted.  This is the
	 * case on the server on which we have to trust the client anyway,
	 * and the user could do anything after logging in.
	 */
	int all_permitted;
};

struct permission {
	char *host_to_connect;		/* Connect to 'host'. */
	int port_to_connect;		/* Connect to 'port'. */
	char *listen_host;		/* Remote side should listen address. */
	char *listen_path;		/* Remote side should listen path. */
	int listen_port;		/* Remote side should listen port. */
	Channel *downstream;		/* Downstream mux*/
};

struct ssh_channels {
	/*
	 * Pointer to an array containing all allocated channels.  The array
	 * is dynamically extended as needed.
	 */
	Channel **channels;

	/*
	 * Size of the channel array.  All slots of the array must always be
	 * initialized (at least the type field); unused slots set to NULL
	 */
	u_int channels_alloc;

	/*
	 * Maximum file descriptor value used in any of the channels.  This is
	 * updated in channel_new.
	 */
	int channel_max_fd;

	/*
	 * 'channel_pre*' are called just before select() to add any bits
	 * relevant to channels in the select bitmasks.
	 *
	 * 'channel_post*': perform any appropriate operations for
	 * channels which have events pending.
	 */
	chan_fn **channel_pre;
	chan_fn **channel_post;

	/* -- tcp forwarding */
	struct permission_set local_perms;
	struct permission_set remote_perms;

	/* -- X11 forwarding */

	/* Saved X11 local (client) display. */
	char *x11_saved_display;

	/* Saved X11 authentication protocol name. */
	char *x11_saved_proto;

	/* Saved X11 authentication data.  This is the real data. */
	char *x11_saved_data;
	u_int x11_saved_data_len;

	/* Deadline after which all X11 connections are refused */
	u_int x11_refuse_time;

	/*
	 * Fake X11 authentication data.  This is what the server will be
	 * sending us; we should replace any occurrences of this by the
	 * real data.
	 */
	u_char *x11_fake_data;
	u_int x11_fake_data_len;

	/* AF_UNSPEC or AF_INET or AF_INET6 */
	int IPv4or6;
};