/* $OpenBSD: misc.h,v 1.95 2021/04/03 06:18:40 djm Exp $ */

/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 */

#ifndef _MISC_H
#define _MISC_H

#include <sys/types.h>
#include <stdio.h>

/* Data structure for representing a forwarding request. */
struct Forward {
	char	 *listen_host;		/* Host (address) to listen on. */
	int	  listen_port;		/* Port to forward. */
	char	 *listen_path;		/* Path to bind domain socket. */
	char	 *connect_host;		/* Host to connect. */
	int	  connect_port;		/* Port to connect on connect_host. */
	char	 *connect_path;		/* Path to connect domain socket. */
	int	  allocated_port;	/* Dynamically allocated listen port */
	int	  handle;		/* Handle for dynamic listen ports */
};

int forward_equals(const struct Forward *, const struct Forward *);
int daemonized(void);

/* Common server and client forwarding options. */
struct ForwardOptions {
	int	 gateway_ports; /* Allow remote connects to forwarded ports. */
	int	 streamlocal_bind_mask; /* umask for streamlocal binds */
	int	 streamlocal_bind_unlink; /* unlink socket before bind */
};

/* misc.c */

char	*chop(char *);
void	skip_space(char **);
char	*strdelim(char **);
char	*strdelimw(char **);
int	 set_nonblock(int);
int	 unset_nonblock(int);
void	 set_nodelay(int);
int	 set_reuseaddr(int);
char	*get_rdomain(int);
int	 set_rdomain(int, const char *);
int	 get_sock_af(int);
void	 set_sock_tos(int, int);
int	 waitrfd(int, int *);
int	 a2port(const char *);
int	 a2tun(const char *, int *);
char	*put_host_port(const char *, u_short);
char	*hpdelim2(char **, char *);
char	*hpdelim(char **);
char	*cleanhostname(char *);
char	*colon(char *);
int	 parse_user_host_path(const char *, char **, char **, char **);
int	 parse_user_host_port(const char *, char **, char **, int *);
int	 parse_uri(const char *, const char *, char **, char **, int *, char **);

char	*dollar_expand(int *, const char *string, ...);
char	*percent_expand(const char *, ...) __attribute__((__sentinel__));
char	*percent_dollar_expand(const char *, ...) __attribute__((__sentinel__));
char	*tohex(const void *, size_t);
void	 xextendf(char **s, const char *sep, const char *fmt, ...)
    __attribute__((__format__ (printf, 3, 4))) __attribute__((__nonnull__ (3)));
void	 sanitise_stdfd(void);
void	 lowercase(char *s);
int	 unix_listener(const char *, int, int);
int	 valid_domain(char *, int, const char **);
int	 valid_env_name(const char *);
const char *atoi_err(const char *, int *);
int	 path_absolute(const char *);
int	 stdfd_devnull(int, int, int);

void	 sock_set_v6only(int);

struct passwd *pwcopy(struct passwd *);
const char *ssh_gai_strerror(int);

typedef void privdrop_fn(struct passwd *);
typedef void privrestore_fn(void);
#define	SSH_SUBPROCESS_STDOUT_DISCARD	(1)     /* Discard stdout */
#define	SSH_SUBPROCESS_STDOUT_CAPTURE	(1<<1)  /* Redirect stdout */
#define	SSH_SUBPROCESS_STDERR_DISCARD	(1<<2)  /* Discard stderr */
#define	SSH_SUBPROCESS_UNSAFE_PATH	(1<<3)	/* Don't check for safe cmd */
#define	SSH_SUBPROCESS_PRESERVE_ENV	(1<<4)	/* Keep parent environment */


typedef struct arglist arglist;
struct arglist {
	char    **list;
	u_int   num;
	u_int   nalloc;
};
void	 addargs(arglist *, char *, ...)
	    __attribute__((format(printf, 2, 3)));
void	 replacearg(arglist *, u_int, char *, ...)
	    __attribute__((format(printf, 3, 4)));
void	 freeargs(arglist *);

int	 tun_open(int, int, char **);

/* Common definitions for ssh tunnel device forwarding */
#define SSH_TUNMODE_NO		0x00
#define SSH_TUNMODE_POINTOPOINT	0x01
#define SSH_TUNMODE_ETHERNET	0x02
#define SSH_TUNMODE_DEFAULT	SSH_TUNMODE_POINTOPOINT
#define SSH_TUNMODE_YES		(SSH_TUNMODE_POINTOPOINT|SSH_TUNMODE_ETHERNET)

#define SSH_TUNID_ANY		0x7fffffff
#define SSH_TUNID_ERR		(SSH_TUNID_ANY - 1)
#define SSH_TUNID_MAX		(SSH_TUNID_ANY - 2)

/* Fake port to indicate that host field is really a path. */
#define PORT_STREAMLOCAL	-2


int parse_ipqos(const char *);
const char *iptos2str(int);
void mktemp_proto(char *, size_t);

void	 child_set_env(char ***envp, u_int *envsizep, const char *name,
	    const char *value);

int	 argv_split(const char *, int *, char ***);
char	*argv_assemble(int, char **argv);

struct stat;

int	 safe_path_fd(int, const char *, struct passwd *,
	    char *err, size_t errlen);

/* authorized_key-style options parsing helpers */
int	opt_flag(const char *opt, int allow_negate, const char **optsp);
char	*opt_dequote(const char **sp, const char **errstrp);
int	opt_match(const char **opts, const char *term);

/* readconf/servconf option lists */
void	opt_array_append(const char *file, const int line,
	    const char *directive, char ***array, u_int *lp, const char *s);
void	opt_array_append2(const char *file, const int line,
	    const char *directive, char ***array, int **iarray, u_int *lp,
	    const char *s, int i);

/* readpass.c */

#define RP_ECHO			0x0001
#define RP_ALLOW_STDIN		0x0002
#define RP_ALLOW_EOF		0x0004
#define RP_USE_ASKPASS		0x0008

struct notifier_ctx;

char	*read_passphrase(const char *, int);
int	 ask_permission(const char *, ...) __attribute__((format(printf, 1, 2)));
struct notifier_ctx *notify_start(int, const char *, ...)
	__attribute__((format(printf, 2, 3)));
void	notify_complete(struct notifier_ctx *, const char *, ...)
	__attribute__((format(printf, 2, 3)));

#define MINIMUM(a, b)	(((a) < (b)) ? (a) : (b))
#define MAXIMUM(a, b)	(((a) > (b)) ? (a) : (b))
#define ROUNDUP(x, y)   ((((x)+((y)-1))/(y))*(y))

typedef void (*sshsig_t)(int);
sshsig_t ssh_signal(int, sshsig_t);

#endif /* _MISC_H */
