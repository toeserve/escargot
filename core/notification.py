import asyncio
from collections import defaultdict
from enum import IntFlag

from .models import User, Group, Lst, Contact, UserStatus
from .event import PresenceNotificationEvent, AddedToListEvent, InvitedToChatEvent, ChatParticipantLeft, ChatParticipantJoined, ChatMessage
from . import error

class Ack(IntFlag):
	Zero = 0
	NAK = 1
	ACK = 2
	Full = 3

class ServiceAddress:
	def __init__(self, host, port):
		self.host = host
		self.port = port

class NotificationServer:
	def __init__(self, loop, user_service, auth_service):
		self._user_service = user_service
		self._auth_service = auth_service
		self._sbservices = [ServiceAddress('m1.escargot.log1p.xyz', 1864)]
		
		self._ncs = _NSSessCollection()
		# Dict[User.uuid, User]
		self._user_by_uuid = {}
		# Dict[User, UserDetail]
		self._unsynced_db = {}
		
		loop.create_task(self._sync_db())
	
	def on_connection_lost(self, sess):
		user = sess.user
		if user is None: return
		self._ncs.remove_nc(sess)
		if self._ncs.get_ncs_by_user(user):
			# There are still other people logged in as this user,
			# so don't send offline notifications.
			return
		# User is offline, send notifications
		user.detail = None
		self._sync_contact_statuses()
		self._generic_notify(sess)
	
	def login_md5_get_salt(self, email):
		return self._user_service.get_md5_salt(email)
	
	def login_md5_verify(self, sess, email, md5_hash):
		uuid = self._user_service.login_md5(email, md5_hash)
		return self._login_common(sess, uuid, email, token)
	
	def login_twn_start(self, email, password):
		uuid = self._user_service.login(email, password)
		if uuid is None: return None
		return self._auth_service.create_token('nb/login', uuid)
	
	def login_twn_verify(self, sess, email, token):
		uuid = self._auth_service.pop_token('nb/login', token)
		return self._login_common(sess, uuid, email, token)
	
	def _login_common(self, sess, uuid, email, token):
		if uuid is None: return None
		self._user_service.update_date_login(uuid)
		user = self._load_user_record(uuid)
		sess.user = user
		sess.token = token
		self._ncs.add_nc(sess)
		user.detail = self._load_detail(user)
		return user
	
	def _load_user_record(self, uuid):
		if uuid not in self._user_by_uuid:
			user = self._user_service.get(uuid)
			if user is None: return None
			self._user_by_uuid[uuid] = user
		return self._user_by_uuid[uuid]
	
	def _load_detail(self, user):
		if user.detail: return user.detail
		return self._user_service.get_detail(user.uuid)
	
	def _generic_notify(self, sess):
		# Notify relevant `Session`s of status, name, message, media
		user = sess.user
		if user is None: return
		for sess_other in self._ncs.get_ncs():
			if sess_other == sess: continue
			user_other = sess_other.user
			if user_other.detail is None: continue
			ctc = user_other.detail.contacts.get(user.uuid)
			if ctc is None: continue
			sess_other.send_event(PresenceNotificationEvent(ctc))
	
	def _sync_contact_statuses(self):
		# Recompute all `Contact.status`'s
		for user in self._user_by_uuid.values():
			detail = user.detail
			if detail is None: continue
			for ctc in detail.contacts.values():
				ctc.compute_visible_status(user)
	
	def _mark_modified(self, user, *, detail = None):
		ud = user.detail or detail
		if detail: assert ud is detail
		assert ud is not None
		self._unsynced_db[user] = ud
	
	def sb_token_create(self, sess, *, extra_data = None):
		token = self._auth_service.create_token('sb/xfr', { 'uuid': sess.user.uuid, 'extra_data': extra_data })
		sb_address = self._sbservices[0]
		return (token, sb_address)
	
	def me_update(self, sess, fields):
		user = sess.user
		
		if 'message' in fields:
			user.status.message = fields['message']
		if 'media' in fields:
			user.status.media = fields['media']
		if 'name' in fields:
			user.status.name = fields['name']
		if 'gtc' in fields:
			user.detail.settings['gtc'] = fields['gtc']
		if 'blp' in fields:
			user.detail.settings['blp'] = fields['blp']
		if 'substatus' in fields:
			user.status.substatus = fields['substatus']
		if 'capabilities' in fields:
			user.detail.capabilities = fields['capabilities']
		if 'msnobj' in fields:
			user.detail.msnobj = fields['msnobj']
		
		self._mark_modified(user)
		self._sync_contact_statuses()
		self._generic_notify(sess)
	
	def me_group_add(self, sess, name):
		if len(name) > MAX_GROUP_NAME_LENGTH:
			raise error.GroupNameTooLong()
		user = sess.user
		group = Group(_gen_group_id(user.detail), name)
		user.detail.groups[group.id] = group
		self._mark_modified(user)
		return group
	
	def me_group_remove(self, sess, group_id):
		if group_id == '0':
			raise error.CannotRemoveSpecialGroup()
		user = sess.user
		try:
			del user.detail.groups[group_id]
		except KeyError:
			raise error.GroupDoesNotExist()
		for ctc in user.detail.contacts.values():
			ctc.groups.discard(group_id)
		self._mark_modified(user)
	
	def me_group_edit(self, sess, group_id, new_name):
		user = sess.user
		g = user.detail.groups.get(group_id)
		if g is None:
			raise error.GroupDoesNotExist()
		if len(name) > MAX_GROUP_NAME_LENGTH:
			raise error.GroupNameTooLong()
		g.name = name
		self._mark_modified(user)
	
	def me_group_contact_add(self, sess, group_id, contact_uuid):
		if group_id == '0': return
		user = sess.user
		detail = user.detail
		if group_id not in detail.groups:
			raise error.GroupDoesNotExist()
		ctc = detail.contacts.get(contact_uuid)
		if ctc is None:
			raise error.ContactDoesNotExist()
		if group_id in ctc.groups:
			raise error.ContactAlreadyOnList()
		ctc.groups.add(group_id)
		self._mark_modified(user)
	
	def me_group_contact_remove(self, sess, group_id, contact_uuid):
		user = sess.user
		detail = user.detail
		ctc = detail.contacts.get(contact_uuid)
		if ctc is None:
			raise error.ContactDoesNotExist()
		if group_id not in detail.groups and group_id != '0':
			raise error.GroupDoesNotExist()
		try:
			ctc.groups.remove(group_id)
		except KeyError:
			if group_id == '0':
				raise error.ContactNotOnList()
		self._mark_modified(user)
	
	def me_contact_add(self, sess, contact_uuid, lst, name):
		ctc_head = self._load_user_record(contact_uuid)
		if ctc_head is None:
			raise error.UserDoesNotExist()
		user = sess.user
		ctc = self._add_to_list(user, ctc_head, lst, name)
		if lst is Lst.FL:
			# FL needs a matching RL on the contact
			self._add_to_list(ctc_head, user, Lst.RL, user.status.name)
			self._notify_reverse_add(sess, ctc_head)
		self._sync_contact_statuses()
		self._generic_notify(sess)
		return ctc, ctc_head
	
	def _notify_reverse_add(self, sess, user_added):
		user_adder = sess.user
		# `user_added` was added to `user_adder`'s RL
		for sess_added in self._ncs.get_ncs_by_user(user_added):
			if sess_added == sess: continue
			sess_added.send_event(AddedToListEvent(Lst.RL, user_adder))
	
	def me_contact_edit(self, sess, contact_uuid, *, is_messenger_user = None, is_favorite = None):
		user = sess.user
		ctc = user.detail.contacts.get(contact_uuid)
		if ctc is None:
			raise error.ContactDoesNotExist()
		if is_messenger_user is not None:
			ctc.is_messenger_user = is_messenger_user
		if is_favorite is not None:
			ctc.is_favorite = is_favorite
		self._mark_modified(user)
	
	def me_contact_remove(self, sess, contact_uuid, lst):
		user = sess.user
		ctc = user.detail.contacts.get(contact_uuid)
		if ctc is None:
			raise error.ContactDoesNotExist()
		if lst is Lst.FL:
			# Remove from FL
			self._remove_from_list(user, ctc.head, Lst.FL)
			# Remove matching RL
			self._remove_from_list(ctc.head, user, Lst.RL)
		else:
			assert lst is not Lst.RL
			ctc.lists &= ~lst
		self._mark_modified(user)
		self._sync_contact_statuses()
	
	def _add_to_list(self, user, ctc_head, lst, name):
		# Add `ctc_head` to `user`'s `lst`
		detail = self._load_detail(user)
		contacts = detail.contacts
		if ctc_head.uuid not in contacts:
			contacts[ctc_head.uuid] = Contact(ctc_head, set(), 0, UserStatus(name))
		ctc = contacts.get(ctc_head.uuid)
		if ctc.status.name is None:
			ctc.status.name = name
		ctc.lists |= lst
		self._mark_modified(user, detail = detail)
		return ctc
	
	def _remove_from_list(self, user, ctc_head, lst):
		# Remove `ctc_head` from `user`'s `lst`
		detail = self._load_detail(user)
		contacts = detail.contacts
		ctc = contacts.get(ctc_head.uuid)
		if ctc is None: return
		ctc.lists &= ~lst
		if not ctc.lists:
			del contacts[ctc_head.uuid]
		self._mark_modified(user, detail = detail)
	
	def util_get_uuid_from_email(self, email):
		return self._user_service.get_uuid(email)
	
	def util_get_sess_by_token(self, token):
		return self._ncs.get_nc_by_token(token)
	
	def notify_call(self, caller_uuid, callee_email, chatid):
		caller = self._user_by_uuid.get(caller_uuid)
		if caller is None: raise error.ServerError()
		if caller.detail is None: raise error.ServerError()
		callee_uuid = self._user_service.get_uuid(callee_email)
		if callee_uuid is None: raise error.UserDoesNotExist()
		ctc = caller.detail.contacts.get(callee_uuid)
		if ctc is None: raise error.ContactDoesNotExist()
		if ctc.status.is_offlineish(): raise error.ContactNotOnline()
		ctc_ncs = self._ncs.get_ncs_by_user(ctc.head)
		if not ctc_ncs: raise error.ContactNotOnline()
		
		sb_address = self._sbservices[0]
		for ctc_nc in ctc_ncs:
			token = self._auth_service.create_token('sb/cal', { 'uuid': ctc.head.uuid, 'extra_data': ctc_nc.state.get_sb_extra_data() })
			ctc_nc.send_event(InvitedToChatEvent(sb_address, chatid, token, caller))
	
	async def _sync_db(self):
		while True:
			await asyncio.sleep(1)
			self._sync_db_impl()
	
	def _sync_db_impl(self):
		if not self._unsynced_db: return
		try:
			users = list(self._unsynced_db.keys())[:100]
			batch = []
			for user in users:
				detail = self._unsynced_db.pop(user, None)
				if not detail: continue
				batch.append((user, detail))
			self._user_service.save_batch(batch)
		except Exception:
			import traceback
			traceback.print_exc()

class _NSSessCollection:
	def __init__(self):
		# Dict[User, Set[Session]]
		self._ncs_by_user = defaultdict(set)
		# Dict[Session.token, Session]
		self._nc_by_token = {}
	
	def get_ncs_by_user(self, user):
		if user not in self._ncs_by_user:
			return ()
		return self._ncs_by_user[user]
	
	def get_ncs(self):
		for ncs in self._ncs_by_user.values():
			yield from ncs
	
	def get_nc_by_token(self, token):
		return self._nc_by_token.get(token)
	
	def add_nc(self, nc):
		assert nc.user
		self._ncs_by_user[nc.user].add(nc)
		if nc.token:
			self._nc_by_token[nc.token] = nc
	
	def remove_nc(self, nc):
		assert nc.user
		self._ncs_by_user[nc.user].discard(nc)
		if nc.token:
			del self._nc_by_token[nc.token]

def _gen_group_id(detail):
	id = 1
	s = str(id)
	while s in detail.groups:
		id += 1
		s = str(id)
	return s

MAX_GROUP_NAME_LENGTH = 61