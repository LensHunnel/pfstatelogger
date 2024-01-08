from .messages import MessageState, MessageDeleteCompressed, MessageClear, MessageInsertAck, MessageUpdateReq, MessageUpdateCompressed


class BaseAction(object):
    """
    This class represents a base action

    """
    def __init__(self, shdr):
        self.header = shdr
        self.messages = []

    @classmethod
    def get_message_class(cls):
        """
        This method returns the message class associated with the
        action (cls.message_class by default)

        If cls.message_class is not provided, this method MUST be
        overriden

        """
        return cls.message_class

    @classmethod
    def from_data(cls, data, shdr):
        """
        This method extracts the messages from data and return
        a populated Action class and the rest of the data

        """
        msg_class = cls.get_message_class()
        action = cls(shdr)
        for _ in range(shdr.count):
            (msg, data) = msg_class.from_data(data)
            action.messages.append(msg)
        return (action, data)


class ActionInsertState(BaseAction):
    """Action class related to inserting states"""
    message_class = MessageState


class ActionUpdateState(BaseAction):
    """Action class related to inserting states"""
    message_class = MessageState



class ActionDeleteState(BaseAction):
    """Action class related to deleting states"""
    message_class = MessageState


class ActionDeleteCompressedState(BaseAction):
    """Action class related to pfsync_del_c action"""
    message_class = MessageDeleteCompressed


class ActionClearStates(BaseAction):
    """Action class related to pfsync_clr action"""
    message_class = MessageClear

class ActionInsertAck(BaseAction):
    """Action class related to pfsync_clr action"""
    message_class = MessageInsertAck


class ActionUpdateRequestState(BaseAction):
    """Action class related to pfsync_clr action"""
    message_class = MessageUpdateReq


class ActionUpdateCompressedState(BaseAction):
    """Action class related to pfsync_clr action"""
    message_class = MessageUpdateCompressed


def build_from_header(shdr, data):
    """
    This function returns an instance of the class corresponding to the
    action type supplied in the header

    shdr is of type pfsync.headers.SubHeader

    If no action class is supplied below, this function extract the
    needed amount of data in order to not pollute the rest of the program

    Actions ID corresponds to these defines:

    #define	PFSYNC_ACT_CLR		0	/* clear all states */
    #define	PFSYNC_ACT_INS_1301	1	/* insert state */
    #define	PFSYNC_ACT_INS_ACK	2	/* ack of inserted state */
    #define	PFSYNC_ACT_UPD_1301	3	/* update state */
    #define	PFSYNC_ACT_UPD_C	4	/* "compressed" update state */
    #define	PFSYNC_ACT_UPD_REQ	5	/* request "uncompressed" state */
    #define	PFSYNC_ACT_DEL		6	/* delete state */
    #define	PFSYNC_ACT_DEL_C	7	/* "compressed" delete state */
    #define	PFSYNC_ACT_INS_F	8	/* insert fragment */
    #define	PFSYNC_ACT_DEL_F	9	/* delete fragments */
    #define	PFSYNC_ACT_BUS		10	/* bulk update status */
    #define	PFSYNC_ACT_TDB		11	/* TDB replay counter update */
    #define	PFSYNC_ACT_EOF		12	/* end of frame */
    #define PFSYNC_ACT_INS_1400	13	/* insert state */
    #define PFSYNC_ACT_UPD_1400	14	/* update state */
    #define	PFSYNC_ACT_MAX		15


    See OpenBSD sources sys/net/if_pfsync.h

    """
    actions = [
        ActionClearStates,
        ActionInsertState,
        ActionInsertAck,
        ActionUpdateState,
        ActionUpdateCompressedState,
        ActionUpdateRequestState,
        ActionDeleteState,
        ActionDeleteCompressedState,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
        ]
    # print(f"action ID: {shdr.action_id} - data={data}")

    if shdr.action_id >= 0 and shdr.action_id < len(actions) and actions[shdr.action_id]:
        return actions[shdr.action_id].from_data(data, shdr)
    else:
        data = ""
        return (None, data)
