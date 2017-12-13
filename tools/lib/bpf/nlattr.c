
/*
 * NETLINK      Netlink attributes
 *
 *		Authors:	Thomas Graf <tgraf@suug.ch>
 *				Alexey Kuznetsov <kuznet@ms2.inr.ac.ru>
 */

#include <errno.h>
#include "nlattr.h"
#include <linux/rtnetlink.h>
#include <string.h>
#include <stdio.h>

static const __u8 nla_attr_minlen[NLA_TYPE_MAX+1] = {
	[NLA_U8]	= sizeof(__u8),
	[NLA_U16]	= sizeof(__u16),
	[NLA_U32]	= sizeof(__u32),
	[NLA_U64]	= sizeof(__u64),
	[NLA_MSECS]	= sizeof(__u64),
	[NLA_NESTED]	= NLA_HDRLEN,
	[NLA_S8]	= sizeof(__s8),
	[NLA_S16]	= sizeof(__s16),
	[NLA_S32]	= sizeof(__s32),
	[NLA_S64]	= sizeof(__s64),
};

static int validate_nla(const struct nlattr *nla, int maxtype,
			const struct nla_policy *policy)
{
	const struct nla_policy *pt;
	int minlen = 0, attrlen = nla_len(nla), type = nla_type(nla);

	if (type <= 0 || type > maxtype)
		return 0;

	pt = &policy[type];

	if (pt->type > NLA_TYPE_MAX)
		return -EINVAL;

	switch (pt->type) {
	case NLA_FLAG:
		if (attrlen > 0)
			return -ERANGE;
		break;

	case NLA_NUL_STRING:
		if (pt->len)
			minlen = min(attrlen, pt->len + 1);
		else
			minlen = attrlen;

		if (!minlen || memchr(nla_data(nla), '\0', minlen) == NULL)
			return -EINVAL;
		/* fall through */

	case NLA_STRING:
		if (attrlen < 1)
			return -ERANGE;

		if (pt->len) {
			char *buf = nla_data(nla);

			if (buf[attrlen - 1] == '\0')
				attrlen--;

			if (attrlen > pt->len)
				return -ERANGE;
		}
		break;

	case NLA_BINARY:
		if (pt->len && attrlen > pt->len)
			return -ERANGE;
		break;

	case NLA_NESTED_COMPAT:
		if (attrlen < pt->len)
			return -ERANGE;
		if (attrlen < NLA_ALIGN(pt->len))
			break;
		if (attrlen < NLA_ALIGN(pt->len) + NLA_HDRLEN)
			return -ERANGE;
		nla = nla_data(nla) + NLA_ALIGN(pt->len);
		if (attrlen < NLA_ALIGN(pt->len) + NLA_HDRLEN + nla_len(nla))
			return -ERANGE;
		break;
	case NLA_NESTED:
		/* a nested attributes is allowed to be empty; if its not,
		 * it must have a size of at least NLA_HDRLEN.
		 */
		if (attrlen == 0)
			break;
	default:
		if (pt->len)
			minlen = pt->len;
		else if (pt->type != NLA_UNSPEC)
			minlen = nla_attr_minlen[pt->type];

		if (attrlen < minlen)
			return -ERANGE;
	}

	return 0;
}

/**
 * nla_parse - Parse a stream of attributes into a tb buffer
 * @tb: destination array with maxtype+1 elements
 * @maxtype: maximum attribute type to be expected
 * @head: head of attribute stream
 * @len: length of attribute stream
 * @policy: validation policy
 *
 * Parses a stream of attributes and stores a pointer to each attribute in
 * the tb array accessible via the attribute type. Attributes with a type
 * exceeding maxtype will be silently ignored for backwards compatibility
 * reasons. policy may be set to NULL if no validation is required.
 *
 * Returns 0 on success or a negative error code.
 */
static int nla_parse(struct nlattr **tb, int maxtype, const struct nlattr *head,
	      int len, const struct nla_policy *policy)
{
	const struct nlattr *nla;
	int rem, err;

	memset(tb, 0, sizeof(struct nlattr *) * (maxtype + 1));

	nla_for_each_attr(nla, head, len, rem) {
		__u16 type = nla_type(nla);

		if (type > 0 && type <= maxtype) {
			if (policy) {
				err = validate_nla(nla, maxtype, policy);
				if (err < 0)
					goto errout;
			}

			tb[type] = (struct nlattr *)nla;
		}
	}

	err = 0;
errout:
	return err;
}

/* dump netlink extended ack error message */
int nla_dump_errormsg(struct nlmsghdr *nlh)
{
	const struct nla_policy extack_policy[NLMSGERR_ATTR_MAX + 1] = {
		[NLMSGERR_ATTR_MSG]	= { .type = NLA_STRING },
		[NLMSGERR_ATTR_OFFS]	= { .type = NLA_U32 },
	};
	struct nlattr *tb[NLMSGERR_ATTR_MAX + 1], *attr;
	struct nlmsgerr *err;
	char *errmsg = NULL;
	int hlen, alen;

	/* no TLVs, nothing to do here */
	if (!(nlh->nlmsg_flags & NLM_F_ACK_TLVS))
		return 0;

	err = (struct nlmsgerr *)NLMSG_DATA(nlh);
	hlen = sizeof(*err);

	/* if NLM_F_CAPPED is set then the inner err msg was capped */
	if (!(nlh->nlmsg_flags & NLM_F_CAPPED))
		hlen += nlmsg_len(&err->msg);

	attr = (struct nlattr *) ((void *) err + hlen);
	alen = nlh->nlmsg_len - hlen;

	if (nla_parse(tb, NLMSGERR_ATTR_MAX, attr, alen, extack_policy) != 0) {
		fprintf(stderr,
			"Failed to parse extended error attributes\n");
		return 0;
	}

	if (tb[NLMSGERR_ATTR_MSG])
		errmsg = (char *) nla_data(tb[NLMSGERR_ATTR_MSG]);

	fprintf(stderr, "Kernel error message: %s\n", errmsg);

	return 0;
}
