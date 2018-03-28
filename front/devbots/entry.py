from typing import cast, Optional, List
import asyncio

from core.client import Client
from core.models import Substatus, Lst, Contact, User, TextWithData, MessageData, MessageType
from core.backend import Backend, BackendSession, Chat, ChatSession
from core import event

CLIENT = Client('testbot', '0.1', 'direct')

def register(loop: asyncio.AbstractEventLoop, backend: Backend) -> None:
	for i in range(5):
		uuid = backend.util_get_uuid_from_email('bot{}@bot.log1p.xyz'.format(i))
		assert uuid is not None
		bs = backend.login(uuid, CLIENT, BackendEventHandler())
		assert bs is not None

class BackendEventHandler(event.BackendEventHandler):
	__slots__ = ('bs',)
	
	bs: BackendSession
	
	def on_open(self) -> None:
		self.bs.me_update({ 'substatus': Substatus.NLN })
		print("Bot active:", self.bs.user.status.name)
	
	def on_presence_notification(self, contact: Contact, old_substatus: Substatus) -> None:
		pass
	
	def on_chat_invite(self, chat: Chat, inviter: User, *, invite_msg: Optional[str] = None, roster: Optional[List[str]] = None, voice_chat: Optional[int] = None, existing: bool = False) -> None:
		cs = chat.join('testbot', self.bs, ChatEventHandler(self.bs))
		chat.send_participant_joined(cs)
	
	def on_added_to_list(self, user: User, *, message: Optional[TextWithData] = None) -> None:
		pass
	
	def on_contact_request_denied(self, user: User, message: Optional[str]) -> None:
		pass
	
	def on_pop_boot(self) -> None:
		pass
	
	def on_pop_notify(self) -> None:
		pass

class ChatEventHandler(event.ChatEventHandler):
	__slots__ = ('bs', 'cs')
	
	bs: BackendSession
	cs: ChatSession
	
	def __init__(self, bs: BackendSession) -> None:
		self.bs = bs
	
	def on_open(self) -> None:
		pass
	
	def on_participant_joined(self, cs_other: 'ChatSession') -> None:
		pass
	
	def on_participant_left(self, cs_other: 'ChatSession') -> None:
		pass
	
	def on_invite_declined(self, invited_user: User, *, message: Optional[str] = None) -> None:
		pass
	
	def on_message(self, message: MessageData) -> None:
		if message.type is not MessageType.Chat:
			return
		self.cs.send_message_to_everyone(MessageData(
			sender = self.cs.user,
			type = MessageType.Chat,
			text = "lol :p",
		))