#if !defined(_TRACE_QAIC_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_QAIC_H
#include <linux/tracepoint.h>

#undef TRACE_SYSTEM
#define TRACE_SYSTEM qaic
#define TRACE_INCLUDE_FILE qaic_trace
#define TRACE_INCLUDE_PATH . /* depends on -I in makefile */

TRACE_EVENT(qaic_ioctl,
        TP_PROTO(struct qaic_device *qdev, struct qaic_user *usr,
		unsigned int cmd),
        TP_ARGS(qdev, usr, cmd),
        TP_STRUCT__entry(
		__string(device, dev_name(&qdev->pdev->dev))
		__field(unsigned int, user)
		__field(unsigned int, cmd)
		__field(unsigned int, type)
		__field(unsigned int, nr)
		__field(unsigned int, size)
		__field(unsigned int, dir)
	),
	TP_fast_assign(
		__assign_str(device, dev_name(&qdev->pdev->dev))
                __entry->user =	usr->handle;
                __entry->cmd =	cmd;
                __entry->type =	_IOC_TYPE(cmd);
                __entry->nr =	_IOC_NR(cmd);
                __entry->size =	_IOC_SIZE(cmd);
                __entry->dir =	_IOC_DIR(cmd);
        ),
        TP_printk("%s user:%d cmd:0x%x (%c nr=%d len=%d dir=%d)",
                __get_str(device), __entry->user, __entry->cmd, __entry->type,
		__entry->nr, __entry->size, __entry->dir)
);

DECLARE_EVENT_CLASS(qaic_manage_error,
        TP_PROTO(struct qaic_device *qdev, struct qaic_user *usr,
		const char *msg),
        TP_ARGS(qdev, usr, msg),
        TP_STRUCT__entry(
		__string(device, dev_name(&qdev->pdev->dev))
		__field(unsigned int, user)
		__string(msg, msg)
	),
	TP_fast_assign(
		__assign_str(device, dev_name(&qdev->pdev->dev))
                __entry->user =	usr->handle;
		__assign_str(msg, msg)
        ),
        TP_printk("%s user:%d %s",
                __get_str(device), __entry->user, __get_str(msg))
);

DEFINE_EVENT(qaic_manage_error, manage_error,
        TP_PROTO(struct qaic_device *qdev, struct qaic_user *usr,
		const char *msg),
        TP_ARGS(qdev, usr, msg)
);

DECLARE_EVENT_CLASS(qaic_encdec_error,
        TP_PROTO(struct qaic_device *qdev, const char *msg),
        TP_ARGS(qdev, msg),
        TP_STRUCT__entry(
		__string(device, dev_name(&qdev->pdev->dev))
		__string(msg, msg)
	),
	TP_fast_assign(
		__assign_str(device, dev_name(&qdev->pdev->dev))
		__assign_str(msg, msg)
        ),
        TP_printk("%s %s",
                __get_str(device), __get_str(msg))
);

DEFINE_EVENT(qaic_encdec_error, encode_error,
        TP_PROTO(struct qaic_device *qdev, const char *msg),
        TP_ARGS(qdev, msg)
);

DEFINE_EVENT(qaic_encdec_error, decode_error,
        TP_PROTO(struct qaic_device *qdev, const char *msg),
        TP_ARGS(qdev, msg)
);

#endif /* _TRACE_QAIC_H */
#include <trace/define_trace.h>
