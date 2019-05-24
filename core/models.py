from datetime import datetime
from typing import Dict, Optional, Callable, Set, List, Any, TypeVar, NewType
from enum import Enum, IntEnum, IntFlag
import time

UserID = NewType('UserID', int)

class User:
	__slots__ = ('id', 'uuid', 'email', 'verified', 'status', 'detail', 'settings', 'date_created', 'date_modified')
	
	id: UserID
	uuid: str
	email: str
	verified: bool
	status: 'UserStatus'
	detail: Optional['UserDetail']
	settings: Dict[str, Any]
	date_created: datetime
	date_modified: datetime
	
	def __init__(
		self, id: UserID, uuid: str, email: str, verified: bool, status: 'UserStatus',
		settings: Dict[str, Any], date_created: datetime, date_modified: datetime,
	) -> None:
		self.uuid = uuid
		self.email = email
		self.verified = verified
		# `status`: true status of user
		self.status = status
		self.detail = None
		self.settings = settings
		self.date_created = date_created
		self.date_modified = date_modified

class Contact:
	__slots__ = ('head', '_groups', 'lists', 'status', 'info')
	
	head: User
	_groups: Set['ContactGroupEntry']
	lists: 'Lst'
	status: 'UserStatus'
	info: 'ContactInfo'
	
	def __init__(self, user: User, groups: Set['ContactGroupEntry'], lists: 'Lst', status: 'UserStatus', info: 'ContactInfo') -> None:
		self.head = user
		self._groups = groups
		self.lists = lists
		# `status`: status as known by the contact
		self.status = status
		self.info = info
	
	def compute_visible_status(self, to_user: User) -> None:
		# Set Contact.status based on BLP and Contact.lists
		# If not blocked, Contact.status == Contact.head.status
		if self.head.detail is None or _is_blocking(self.head, to_user):
			self.status.substatus = Substatus.Offline
			return
		true_status = self.head.status
		self.status.substatus = true_status.substatus
		self.status.name = true_status.name
		self.status.set_status_message(true_status.message)
		self.status.media = true_status.media
	
	def is_in_group_id(self, group_id: str) -> bool:
		for cge in self._groups:
			if cge.group_id == group_id:
				return True
		return False
	
	def group_in_entry(self, group: 'Group') -> bool:
		for cge in self._groups:
			if cge.group_id == group.id or cge.group_uuid == group.uuid:
				return True
		return False
	
	def add_group_to_entry(self, group: 'Group') -> None:
		self._groups.add(ContactGroupEntry(
			self.head.uuid, group.id, group.uuid,
		))
	
	def remove_from_group(self, group: 'Group') -> None:
		found_group = None
		for cge in self._groups:
			if cge.group_id == group.id or cge.group_uuid == group.uuid:
				found_group = cge
				break
		if found_group is not None:
			self._groups.discard(cge)

def _is_blocking(blocker: User, blockee: User) -> bool:
	detail = blocker.detail
	assert detail is not None
	contact = detail.contacts.get(blockee.uuid)
	lists = (contact and contact.lists or 0)
	if lists & Lst.BL: return True
	if lists & Lst.AL: return False
	return (blocker.settings.get('BLP', 'AL') == 'BL')

class ContactGroupEntry:
	__slots__ = ('contact_uuid', 'group_id', 'group_uuid')
	
	contact_uuid: str
	group_id: str
	group_uuid: str
	
	def __init__(self, contact_uuid: str, group_id: str, group_uuid: str) -> None:
		self.contact_uuid = contact_uuid
		self.group_id = group_id
		self.group_uuid = group_uuid
	
	def __eq__(self, other: object) -> bool:
		if not isinstance(other, ContactGroupEntry):
			return False
		if self.contact_uuid != other.contact_uuid: return False
		if self.group_id != other.group_id: return False
		if self.group_uuid != other.group_uuid: return False
		return True
	
	def __hash__(self) -> int:
		return hash((self.contact_uuid, self.group_id, self.group_uuid))

class ContactInfo:
	__slots__ = (
		'birthdate', 'anniversary', 'notes', 'display_name',
		'first_name', 'middle_name', 'last_name', 'nickname', 'primary_email_type', 'personal_email', 'work_email',
		'im_email', 'other_email', 'home_phone', 'work_phone', 'fax_phone', 'pager_phone', 'mobile_phone',
		'other_phone', 'personal_website', 'business_website', 'locations', 'annotations',
	)
	
	birthdate: Optional[datetime]
	anniversary: Optional[datetime]
	notes: str
	display_name: str
	first_name: str
	middle_name: str
	last_name: str
	nickname: str
	primary_email_type: str
	personal_email: str
	work_email: str
	im_email: str
	other_email: str
	home_phone: str
	work_phone: str
	fax_phone: str
	pager_phone: str
	mobile_phone: str
	other_phone: str
	personal_website: str
	business_website: str
	locations: Dict[str, 'ContactLocation']
	
	def __init__(self, *,
		display_name: str, birthdate: Optional[datetime] = None, anniversary: Optional[datetime] = None,
		notes: str = '', first_name: str = '', middle_name: str = '', last_name: str = '', nickname: str = '',
		primary_email_type: str = '', personal_email: str = '', work_email: str = '', im_email: str = '',
		other_email: str = '', home_phone: str = '', work_phone: str = '', fax_phone: str = '',
		pager_phone: str = '', mobile_phone: str = '', other_phone: str = '', personal_website: str = '',
		business_website: str = '', locations: Optional[Dict[str, 'ContactLocation']] = None,
	) -> None:
		self.birthdate = birthdate
		self.anniversary = anniversary
		self.notes = notes
		self.display_name = display_name
		self.first_name = first_name
		self.middle_name = middle_name
		self.last_name = last_name
		self.nickname = nickname
		self.primary_email_type = primary_email_type
		self.personal_email = personal_email
		self.work_email = work_email
		self.im_email = im_email
		self.other_email = other_email
		self.home_phone = home_phone
		self.work_phone = work_phone
		self.fax_phone = fax_phone
		self.pager_phone = pager_phone
		self.mobile_phone = mobile_phone
		self.other_phone = other_phone
		self.personal_website = personal_website
		self.business_website = business_website
		self.locations = _default_if_none(locations, {})

class ContactLocation:
	__slots__ = ('type', 'name', 'street', 'city', 'state', 'country', 'zip_code')
	
	type: str
	name: str
	street: str
	city: str
	state: str
	country: str
	zip_code: str
	
	def __init__(self, type: str, *, name: str = '', street: str = '', city: str = '', state: str = '', country: str = '', zip_code: str = '') -> None:
		self.type = type
		self.name = name
		self.street = street
		self.city = city
		self.state = state
		self.country = country
		self.zip_code = zip_code

class UserStatus:
	__slots__ = ('substatus', 'name', '_message', '_persistent', 'media')
	
	substatus: 'Substatus'
	name: Optional[str]
	_message: str
	_persistent: bool
	media: Optional[Any]
	
	def __init__(self, name: Optional[str], message: str = '') -> None:
		self.substatus = Substatus.Offline
		self.name = name
		self._message = message
		self._persistent = True
		self.media = None
	
	@property
	def message(self) -> str:
		return self._message
	
	def set_status_message(self, message: str, *, persistent: bool = True) -> None:
		self._message = message
		self._persistent = persistent
	
	def is_offlineish(self) -> bool:
		return self.substatus.is_offlineish()

class UserDetail:
	__slots__ = ('_groups_by_id', '_groups_by_uuid', 'contacts')
	
	_groups_by_id: Dict[str, 'Group']
	_groups_by_uuid: Dict[str, 'Group']
	contacts: Dict[str, 'Contact']
	
	def __init__(self) -> None:
		self._groups_by_id = {}
		self._groups_by_uuid = {}
		self.contacts = {}
	
	def insert_group(self, grp: 'Group') -> None:
		self._groups_by_id[grp.id] = grp
		self._groups_by_uuid[grp.uuid] = grp
	
	def get_group_by_id(self, id: str) -> Optional['Group']:
		group = None
		
		group = self._groups_by_id.get(id)
		if group is None:
			group = self._groups_by_uuid.get(id)
		
		return group
	
	def get_groups_by_name(self, name: str) -> Optional[List['Group']]:
		groups = [] # type: List[Group]
		for group in self._groups_by_id.values():
			if group.name == name or (group.name.startswith(name) and len(group.name) > len(name) and group.name[len(group.name):].isnumeric()):
				if group not in groups: groups.append(group)
		for group in self._groups_by_uuid.values():
			if group.name == name or (group.name.startswith(name) and len(group.name) > len(name) and group.name[len(group.name):].isnumeric()):
				if group not in groups: groups.append(group)
		return groups or None
	
	def delete_group(self, grp: 'Group') -> None:
		if grp.id in self._groups_by_id:
			del self._groups_by_id[grp.id]
		if grp.uuid in self._groups_by_uuid:
			del self._groups_by_uuid[grp.uuid]

class Group:
	__slots__ = ('id', 'uuid', 'name', 'is_favorite', 'date_modified')
	
	id: str
	uuid: str
	name: str
	is_favorite: bool
	date_modified: datetime
	
	def __init__(self, id: str, uuid: str, name: str, is_favorite: bool, *, date_modified: Optional[datetime] = None) -> None:
		self.id = id
		self.uuid = uuid
		self.name = name
		self.is_favorite = is_favorite
		self.date_modified = date_modified or datetime.utcnow()

class MessageType(Enum):
	Chat = object()
	#CircleXML = object()
	Nudge = object()
	Typing = object()
	TypingDone = object()
	Webcam = object()

class MessageData:
	__slots__ = ('sender', 'type', 'text', 'front_cache')
	
	sender: User
	type: MessageType
	text: Optional[str]
	front_cache: Dict[str, Any]
	
	def __init__(self, *, sender: User, type: MessageType, text: Optional[str] = None) -> None:
		self.sender = sender
		self.type = type
		self.text = text
		self.front_cache = {}

class TextWithData:
	__slots__ = ('text', 'yahoo_utf8')
	
	text: str
	yahoo_utf8: Any
	
	def __init__(self, text: str, yahoo_utf8: Any) -> None:
		self.text = text
		self.yahoo_utf8 = yahoo_utf8

#class CircleMetadata:
#	__slots__ = ('circle_id', 'owner_email', 'owner_friendly', 'circle_name', 'date_modified', 'membership_access', 'request_membership_option', 'is_presence_enabled')
#	
#	circle_id: str
#	owner_email: str
#	owner_friendly: str
#	circle_name: str
#	date_modified: datetime
#	membership_access: int
#	request_membership_option: int
#	is_presence_enabled: bool
#	
#	def __init__(self, circle_id: str, owner_email: str, owner_friendly: str, circle_name: str, date_modified: datetime, membership_access: int, request_membership_option: int, is_presence_enabled: bool) -> None:
#		self.circle_id = circle_id
#		self.owner_email = owner_email
#		self.owner_friendly = owner_friendly
#		self.circle_name = circle_name
#		self.date_modified = date_modified
#		self.membership_access = membership_access
#		self.request_membership_option = request_membership_option
#		self.is_presence_enabled = is_presence_enabled
#
#class CircleMembership:
#	__slots__ = ('circle_id', 'email', 'role', 'state')
#	
#	circle_id: str
#	email: str
#	role: 'CircleRole'
#	state: 'CircleState'
#	
#	def __init__(self, circle_id: str, email: str, role: 'CircleRole', state: 'CircleState'):
#		self.circle_id = circle_id
#		self.email = email
#		self.role = role
#		self.state = state

class OIM:
	__slots__ = (
		'uuid', 'run_id', 'from_email', 'from_friendly', 'from_friendly_encoding', 'from_friendly_charset',
		'from_user_id', 'to_email', 'sent', 'origin_ip', 'oim_proxy', 'headers', 'message', 'utf8',
	)
	
	uuid: str
	run_id: str
	from_email: str
	from_friendly: str
	from_friendly_encoding: str
	from_friendly_charset: str
	from_user_id: Optional[str]
	to_email: str
	sent: datetime
	origin_ip: Optional[str]
	oim_proxy: Optional[str]
	headers: Dict[str, str]
	message: str
	utf8: bool
	
	def __init__(self, uuid: str, run_id: str, from_email: str, from_friendly: str, to_email: str, sent: datetime, message: str, utf8: bool, *, headers: Optional[Dict[str, str]] = None, from_friendly_encoding: Optional[str] = None, from_friendly_charset: Optional[str] = None, from_user_id: Optional[str] = None, origin_ip: Optional[str] = None, oim_proxy: Optional[str] = None) -> None:
		self.uuid = uuid
		self.run_id = run_id
		self.from_email = from_email
		self.from_friendly = from_friendly
		self.from_friendly_encoding = _default_if_none(from_friendly_encoding, 'B')
		self.from_friendly_charset = _default_if_none(from_friendly_charset, 'utf-8')
		self.from_user_id = from_user_id
		self.to_email = to_email
		self.sent = sent
		self.origin_ip = origin_ip
		self.oim_proxy = oim_proxy
		self.headers = _default_if_none(headers, {})
		self.message = message
		self.utf8 = utf8

T = TypeVar('T')
def _default_if_none(x: Optional[T], default: T) -> T:
	if x is None: return default
	return x

class Substatus(Enum):
	Offline = object()
	Online = object()
	Busy = object()
	Idle = object()
	BRB = object()
	Away = object()
	OnPhone = object()
	OutToLunch = object()
	Invisible = object()
	NotAtHome = object()
	NotAtDesk = object()
	NotInOffice = object()
	OnVacation = object()
	SteppedOut = object()
	
	def is_offlineish(self) -> bool:
		return self is Substatus.Offline or self is Substatus.Invisible

class Lst(IntFlag):
	Empty = 0x00
	
	FL = 0x01
	AL = 0x02
	BL = 0x04
	RL = 0x08
	PL = 0x10
	
	label: str
	
	# TODO: This is ugly.
	def __init__(self, id: int) -> None:
		super().__init__()
		# From further discovery, `FL` isn't used officially in any of the membership SOAPs. Skip to `AL`.
		if id == 0x02:
			self.label = "Allow"
		elif id == 0x04:
			self.label = "Block"
		elif id == 0x08:
			self.label = "Reverse"
		else:
			self.label = "Pending"
	
	@classmethod
	def Parse(cls, label: str) -> Optional['Lst']:
		if not hasattr(cls, '_MAP'):
			map = {}
			for lst in cls:
				map[lst.label.lower()] = lst
			setattr(cls, '_MAP', map)
		return getattr(cls, '_MAP').get(label.lower())

class NetworkID(IntEnum):
	# Official MSN types
	WINDOWS_LIVE = 0x01
	OFFICE_COMMUNICATOR = 0x02
	TELEPHONE = 0x04
	MNI = 0x08 # Mobile Network Interop, used by Vodafone
	CIRCLE = 0x09
	SMTP = 0x10 # Jaguire, Japanese mobile interop
	YAHOO = 0x20

#class CircleRole(IntEnum):
#	Empty = 0
#	Admin = 1
#	AssistantAdmin = 2
#	Member = 3
#	StatePendingOutbound = 4
#
#class CircleState(IntEnum):
#	Empty = 0
#	WaitingResponse = 1
#	Left = 2
#	Accepted = 3
#	Rejected = 4

class Service:
	__slots__ = ('host', 'port')
	
	host: str
	port: int
	
	def __init__(self, host: str, port: int) -> None:
		self.host = host
		self.port = port

class LoginOption(Enum):
	BootOthers = object()
	NotifyOthers = object()
	Duplicate = object()
