from typing import Any, Tuple, List, Optional, Tuple
from enum import IntEnum
from datetime import datetime
import secrets
import sys

from aiohttp import web
from dateutil import parser as iso_parser

from core import models
from core.backend import Backend, BackendSession, MAX_GROUP_NAME_LENGTH
import util.misc
import settings

from .util import preprocess_soap, get_tag_localname, unknown_soap, find_element, render, bool_to_str

def register(app: web.Application) -> None:
	app.router.add_post('/abservice/SharingService.asmx', handle_abservice)
	app.router.add_post('/abservice/abservice.asmx', handle_abservice)

async def handle_abservice(req: web.Request) -> web.Response:
	header, action, bs, token = await preprocess_soap(req)
	if bs is None:
		raise web.HTTPForbidden()
	action_str = get_tag_localname(action)
	if find_element(action, 'deltasOnly') or find_element(action, 'DeltasOnly'):
		return render(req, 'msn:abservice/Fault.fullsync.xml', { 'faultactor': action_str })
	
	#print(_xml_to_string(action))
	
	try:
		method = getattr(sys.modules[__name__], 'ab_' + action_str)
		return method(req, header, action, bs)
	except Exception as ex:
		import traceback
		return render(req, 'msn:Fault.generic.xml', {
			'exception': traceback.format_exc(),
		})
	
	return unknown_soap(req, header, action)

def ab_FindMembership(req: web.Request, header: Any, action: Any, bs: BackendSession) -> web.Response:
	user = bs.user
	detail = user.detail
	assert detail is not None
	
	return render(req, 'msn:sharing/FindMembershipResponse.xml', {
		'cachekey': _make_cache_key(),
		'host': settings.LOGIN_HOST,
		'session_id': util.misc.gen_uuid(),
		'user': bs.user,
		'detail': detail,
		'lists': [models.Lst.AL, models.Lst.BL, models.Lst.RL, models.Lst.PL],
		'now': _make_now_str(),
	})

def ab_AddMember(req: web.Request, header: Any, action: Any, bs: BackendSession) -> web.Response:
	user = bs.user
	detail = user.detail
	assert detail is not None
	
	backend: Backend = req.app['backend']
	
	memberships = action.findall('.//{*}memberships/{*}Membership')
	for membership in memberships:
		lst = models.Lst.Parse(str(find_element(membership, 'MemberRole')))
		assert lst is not None
		members = membership.findall('.//{*}Members/{*}Member')
		for member in members:
			member_type = member.get('{http://www.w3.org/2001/XMLSchema-instance}type')
			if member_type == 'PassportMember':
				if find_element(member, 'Type') == 'Passport' and find_element(member, 'State') == 'Accepted':
					email = find_element(member, 'PassportName')
			elif member_type == 'EmailMember':
				if find_element(member, 'Type') == 'Email' and find_element(member, 'State') == 'Accepted':
					email = find_element(member, 'Email')
			assert email is not None
			contact_uuid = backend.util_get_uuid_from_email(email)
			assert contact_uuid is not None
			try:
				bs.me_contact_add(contact_uuid, lst, name = email)
			except:
				pass
	return render(req, 'msn:sharing/AddMemberResponse.xml', {
		'cachekey': _make_cache_key(),
		'host': settings.LOGIN_HOST,
		'session_id': util.misc.gen_uuid(),
	})

def ab_DeleteMember(req: web.Request, header: Any, action: Any, bs: BackendSession) -> web.Response:
	user = bs.user
	detail = user.detail
	assert detail is not None
	
	backend: Backend = req.app['backend']
	
	memberships = action.findall('.//{*}memberships/{*}Membership')
	for membership in memberships:
		lst = models.Lst.Parse(str(find_element(membership, 'MemberRole')))
		assert lst is not None
		members = membership.findall('.//{*}Members/{*}Member')
		for member in members:
			member_type = member.get('{http://www.w3.org/2001/XMLSchema-instance}type')
			if member_type == 'PassportMember':
				if find_element(member, 'Type') == 'Passport' and find_element(member, 'State') == 'Accepted':
					contact_uuid = find_element(member, 'MembershipId').split('/', 1)[1]
			elif member_type == 'EmailMember':
				if find_element(member, 'Type') == 'Email' and find_element(member, 'State') == 'Accepted':
					email = find_element(member, 'Email')
					assert email is not None
					contact_uuid = backend.util_get_uuid_from_email(email)
					assert contact_uuid is not None
			if contact_uuid not in detail.contacts:
				return render(req, 'msn:sharing/Fault.memberdoesnotexist.xml', status = 500)
			try:
				bs.me_contact_remove(contact_uuid, lst)
			except:
				pass
	return render(req, 'msn:sharing/DeleteMemberResponse.xml', {
		'cachekey': _make_cache_key(),
		'host': settings.LOGIN_HOST,
		'session_id': util.misc.gen_uuid(),
	})

def ab_ABFindAll(req: web.Request, header: Any, action: Any, bs: BackendSession) -> web.Response:
	user = bs.user
	detail = user.detail
	assert detail is not None
	
	backend: Backend = req.app['backend']
	
	ab_id = find_element(action, 'abId')
	if ab_id is not None:
		ab_id = str(ab_id)
	else:
		ab_id = '00000000-0000-0000-0000-000000000000'
	
	# TODO: Circles
	if ab_id != '00000000-0000-0000-0000-000000000000':
		return web.HTTPInternalServerError()
	
	ab_created, ab_last_modified, ab_contacts = _get_ab_contents(user)
	
	return render(req, 'msn:abservice/ABFindAllResponse.xml', {
		'cachekey': _make_cache_key(),
		'host': settings.LOGIN_HOST,
		'session_id': util.misc.gen_uuid(),
		'user_creator': user,
		'user_creator_detail': detail,
		'ab_contacts': ab_contacts,
		'now': _make_now_str(),
		'ab_id': ab_id,
		'ab_type': 'Individual',
		'ab_last_modified': ab_last_modified,
		'ab_created': ab_created,
	})

def ab_ABFindContactsPaged(req: web.Request, header: Any, action: Any, bs: BackendSession) -> web.Response:
	user = bs.user
	detail = user.detail
	assert detail is not None
	
	backend: Backend = req.app['backend']
	
	ab_id = find_element(action, 'ABId')
	if ab_id is not None:
		ab_id = str(ab_id)
	else:
		ab_id = '00000000-0000-0000-0000-000000000000'
	
	# TODO: Circles
	
	if ab_id != '00000000-0000-0000-0000-000000000000':
		return web.HTTPInternalServerError()
	
	#circle_info = [(
	#	backend.user_service.msn_get_circle_metadata(circle_id), backend.user_service.msn_get_circle_membership(circle_id, user.email),
	#) for circle_id in detail.subscribed_ab_stores if circle_id.startswith('00000000-0000-0000-0009')]
	
	ab_created, ab_last_modified, ab_contacts = _get_ab_contents(user)
	
	return render(req, 'msn:abservice/ABFindContactsPagedResponse.xml', {
		'cachekey': _make_cache_key(),
		'host': settings.LOGIN_HOST,
		'session_id': util.misc.gen_uuid(),
		'user_creator': user,
		'user_creator_detail': detail,
		'ab_contacts': ab_contacts,
		'now': _make_now_str(),
		#'circle_info': circle_info,
		#'ABRelationshipRole': models.ABRelationshipRole,
		#'ABRelationshipState': models.ABRelationshipState,
		#'signedticket': gen_signedticket_xml(user, backend),
		'ab_id': ab_id,
		'ab_type': 'Individual',
		'ab_created': ab_created,
		'ab_last_modified': ab_last_modified,
	})

def ab_ABContactAdd(req: web.Request, header: Any, action: Any, bs: BackendSession) -> web.Response:
	user = bs.user
	detail = user.detail
	assert detail is not None
	
	backend: Backend = req.app['backend']
	
	ab_id = find_element(action, 'abId')
	if ab_id is not None:
		ab_id = str(ab_id)
	else:
		ab_id = '00000000-0000-0000-0000-000000000000'
	
	if ab_id != '00000000-0000-0000-0000-000000000000':
		return web.HTTPInternalServerError()
	
	contact = find_element(action, 'contacts/Contact')
	
	if contact is None:
		return web.HTTPInternalServerError()
	
	type = find_element(contact, 'contactType') or 'LivePending'
	email = find_element(contact, 'passportName') or ''
	if '@' not in email:
		return render(req, 'msn:abservice/Fault.emailmissingatsign.xml', status = 500)
	elif '.' not in email:
		return render(req, 'msn:abservice/Fault.emailmissingdot.xml', status = 500)
	
	contact_uuid = backend.util_get_uuid_from_email(email)
	if contact_uuid is None:
		return render(req, 'msn:abservice/Fault.invaliduser.xml', {
			'email': email,
		}, status = 500)
	
	ctc_ab = backend.user_service.ab_get_entry_by_email(email, type, user)
	if ctc_ab is not None:
		return render(req, 'msn:abservice/Fault.contactalreadyexists.xml', status = 500)
	
	#TODO: How does `LivePending` work and how are we expected to switch it to `Regular` afterwards?
	
	ctc = detail.contacts.get(contact_uuid)
	if ctc:
		groups = { cge.group_uuid for cge in ctc._groups }
	else:
		groups = set()
	annotations = contact.findall('.//{*}annotations/{*}Annotation')
	annotations_dict = {}
	nickname = None
	if annotations:
		for annotation in annotations:
			name = find_element(annotation, 'Name')
			if name not in _ANNOTATION_NAMES:
				return web.HTTPInternalServerError()
			value = find_element(annotation, 'Value')
			if name is 'AB.NickName':
				nickname = value
			else:
				annotations_dict[name] = value
	is_messenger_user = find_element(contact, 'isMessengerUser')
	ctc_ab = models.AddressBookContact(
		('Regular' if type == 'LivePending' else type), backend.user_service.gen_ab_entry_id(user), util.misc.gen_uuid(), email, email, groups,
		member_uuid = contact_uuid, nickname = nickname, is_messenger_user = is_messenger_user, annotations = {name: value for name, value in annotations_dict.items() if name.startswith('AB.') or name.startswith('Live.')},
	)
	
	'''
	if ab_id == '00000000-0000-0000-0000-000000000000':
		if ctc:
			head = ctc.head
		else:
			head = backend._load_user_record(contact_uuid)
		assert head is not None
		ctc_me_ab = backend.user_service.ab_get_entry_by_email(email, 'LivePending', head)
		ctc_me_new = False
		
		annotations_me = {}
		
		for name in annotations_dict.keys():
			if name == 'MSN.IM.InviteMessage':
				annotations_me[name] = annotations_dict[name]
		
		if ctc_me_ab is None:
			ctc_me_ab = models.AddressBookContact(
				'LivePending', backend.user_service.gen_ab_entry_id(user), util.misc.gen_uuid(), user.email, user.email, set(),
				member_uuid = user.uuid, is_messenger_user = is_messenger_user, annotations = annotations_me,
			)
			ctc_me_new = True
		else:
			if ctc_me_ab.is_messenger_user:
				ctc_me_ab.name = user.status.name or user.email
				ctc_me_ab.annotations.update(annotations_me)
		
		await backend.user_service.mark_ab_modified_async('00000000-0000-0000-0000-000000000000', { 'contacts': [ctc_ab] }, head)
		
		tpl = backend.user_service.get_ab_contents(head)
		assert tpl is not None
		user_creator, _, ab_last_modified, _ = tpl
		
		for ctc_sess in backend.util_get_sessions_by_user(head):
			ctc_sess.evt.msn_on_notify_ab(cid_format(head.uuid), str(util.misc.date_format(ab_last_modified or datetime.utcnow())))
	'''
	
	return render(req, 'msn:abservice/ABContactAddResponse.xml', {
		'cachekey': _make_cache_key(),
		'host': settings.LOGIN_HOST,
		'session_id': util.misc.gen_uuid(),
		'contact_uuid': ctc_ab.uuid,
	})

def ab_ABContactDelete(req: web.Request, header: Any, action: Any, bs: BackendSession) -> web.Response:
	user = bs.user
	detail = user.detail
	assert detail is not None
	
	backend: Backend = req.app['backend']
	
	ab_id = find_element(action, 'abId')
	if ab_id is not None:
		ab_id = str(ab_id)
	else:
		ab_id = '00000000-0000-0000-0000-000000000000'
	
	if ab_id != '00000000-0000-0000-0000-000000000000':
		return web.HTTPInternalServerError()
	
	contacts = action.findall('.//{*}contacts/{*}Contact')
	for contact in contacts:
		contact_uuid = find_element(contact, 'contactId')
		assert contact_uuid is not None
		backend.user_service.ab_delete_entry(contact_uuid, user)
	return render(req, 'msn:abservice/ABContactDeleteResponse.xml', {
		'cachekey': _make_cache_key(),
		'host': settings.LOGIN_HOST,
		'session_id': util.misc.gen_uuid(),
	})

def ab_CreateContact(req: web.Request, header: Any, action: Any, bs: BackendSession) -> web.Response:
	# Used as a step in Circle invites, but also used for regular contact adds in WLM 2011/2012
	raise NotImplementedError()
	'''
	user = bs.user
	detail = user.detail
	assert detail is not None
	
	ab_id = find_element(action, 'ABId')
	if ab_id is not None:
		ab_id = str(ab_id)
	else:
		ab_id = '00000000-0000-0000-0000-000000000000'
	
	if ab_id != '00000000-0000-0000-0000-000000000000:
		return web.HTTPInternalServerError()
	
	contact_email = find_element(action, 'Email')
	
	tpl = backend.user_service.get_ab_contents(user)
	assert tpl is not None
	user_creator, _, _, _ = tpl
	
	contact_uuid = backend.util_get_uuid_from_email(contact_email)
	if contact_uuid is None:
		return web.HTTPInternalServerError()
	
	type = ('Circle' if ab_id.startswith('00000000-0000-0000-0009') else 'Regular')
	
	ctc_ab = backend.user_service.ab_get_entry_by_email(contact_email, type, user)
	if ctc_ab is not None:
		# TODO: Error SOAP
		return web.HTTPInternalServerError()
	
	ctc_ab = models.AddressBookContact(
		type, backend.user_service.gen_ab_entry_id(user), util.misc.gen_uuid(), contact_email, contact_email, set(),
		member_uuid = contact_uuid, is_messenger_user = True,
	)
	
	await backend.user_service.mark_ab_modified_async({ 'contacts': [ctc_ab] }, user)
	
	return render(req, 'msn:abservice/CreateContactResponse.xml', {
		'cachekey': _make_cache_key(),
		'host': settings.LOGIN_HOST,
		'session_id': util.misc.gen_uuid(),
		'ab_id': ab_id,
		'contact': ctc_ab,
		'user_creator_detail': user_creator.detail,
	})
	'''

def ab_ABContactUpdate(req: web.Request, header: Any, action: Any, bs: BackendSession) -> web.Response:
	user = bs.user
	detail = user.detail
	assert detail is not None
	
	backend: Backend = req.app['backend']
	
	ctc = None
	ctc_ab = None
	contacts_to_update = []
	
	ab_id = find_element(action, 'abId')
	if ab_id is not None:
		ab_id = str(ab_id)
	else:
		ab_id = '00000000-0000-0000-0000-000000000000'
	
	if ab_id != '00000000-0000-0000-0000-000000000000':
		return web.HTTPInternalServerError()
	
	contacts = action.findall('.//{*}contacts/{*}Contact')
	for contact in contacts:
		contact_info = find_element(contact, 'contactInfo')
		if find_element(contact_info, 'contactType') == 'Me':
			contact_uuid = user.uuid
		else:
			contact_uuid = find_element(contact, 'contactId')
		if not contact_uuid:
			return web.HTTPInternalServerError()
		if contact_uuid is not user.uuid:
			ctc_ab = backend.user_service.ab_get_entry_by_uuid(contact_uuid, user)
			if not ctc_ab:
				return web.HTTPInternalServerError()
		properties_changed = contact.find('./{*}propertiesChanged')
		if not properties_changed:
			return web.HTTPInternalServerError()
		properties_changed = str(properties_changed).strip().split(' ')
		for contact_property in properties_changed:
			if contact_property not in _CONTACT_PROPERTIES:
				return web.HTTPInternalServerError()
		
		for contact_property in properties_changed:
			if contact_property == 'Anniversary':
				assert ctc_ab is not None
				property = find_element(contact_info, 'Anniversary')
				# When `Anniversary` node isn't present, lxml returns `-1` instead of None. What gives?
				try:
					if property not in (None,-1):
						property = str(property)
						property = datetime.strptime(property, '%Y/%m/%d')
				except:
					return web.HTTPInternalServerError()
			if contact_property == 'ContactBirthDate':
				assert ctc_ab is not None
				property = find_element(contact_info, 'birthdate')
				try:
					if property is not None:
						property = str(property)
						if property != '0001-01-01T00:00:00':
							if not property.endswith('Z'):
								return web.HTTPInternalServerError()
							property = iso_parser.parse(property)
				except:
					return web.HTTPInternalServerError()
			if contact_property == 'ContactLocation':
				assert ctc_ab is not None
				contact_locations = contact_info.findall('.//{*}locations/{*}ContactLocation')
				for contact_location in contact_locations:
					if str(find_element(contact_location, 'contactLocationType')) not in ('ContactLocationPersonal','ContactLocationBusiness'):
						return web.HTTPInternalServerError()
					location_properties_changed = find_element(contact_location, 'Changes')
					if location_properties_changed is None:
						return web.HTTPInternalServerError()
					location_properties_changed = str(location_properties_changed).strip().split(' ')
					for location_property in location_properties_changed:
						if location_property not in _CONTACT_LOCATION_PROPERTIES:
							return web.HTTPInternalServerError()
					for location_property in location_properties_changed:
						if location_property == 'Name' and str(find_element(contact_location, 'contactLocationType')) != 'ContactLocationBusiness':
							return web.HTTPInternalServerError()
			if contact_property == 'IsMessengerUser':
				assert ctc_ab is not None
				property = find_element(contact_info, 'isMessengerUser')
				if property is None:
					return web.HTTPInternalServerError()
			if contact_property == 'ContactEmail':
				assert ctc_ab is not None
				contact_emails = contact_info.findall('.//{*}emails/{*}ContactEmail')
				for contact_email in contact_emails:
					email_properties_changed = find_element(contact_email, 'propertiesChanged')
					if email_properties_changed is None:
						return web.HTTPInternalServerError()
					email_properties_changed = str(email_properties_changed).strip().split(' ')
					for email_property in email_properties_changed:
						if email_property not in _CONTACT_EMAIL_PROPERTIES:
							return web.HTTPInternalServerError()
					if str(find_element(contact_email, 'contactEmailType')) not in ('ContactEmailPersonal','ContactEmailBusiness','ContactEmailMessenger','ContactEmailOther'):
						return web.HTTPInternalServerError()
			if contact_property == 'ContactPrimaryEmailType':
				assert ctc_ab is not None
				email_primary_type = str(find_element(contact_info, 'primaryEmailType'))
				if email_primary_type not in ('Passport','ContactEmailPersonal','ContactEmailBusiness','ContactEmailOther'):
					return web.HTTPInternalServerError()
			if contact_property == 'ContactPhone':
				assert ctc_ab is not None
				contact_phones = contact_info.findall('.//{*}phones/{*}ContactPhone')
				for contact_phone in contact_phones:
					phone_properties_changed = find_element(contact_phone, 'propertiesChanged')
					if phone_properties_changed is None:
						return web.HTTPInternalServerError()
					phone_properties_changed = str(phone_properties_changed).strip().split(' ')
					for phone_property in phone_properties_changed:
						if phone_property not in _CONTACT_PHONE_PROPERTIES:
							return web.HTTPInternalServerError()
					if str(find_element(contact_phone, 'contactPhoneType')) not in ('ContactPhonePersonal','ContactPhoneBusiness','ContactPhoneMobile','ContactPhoneFax','ContactPhonePager','ContactPhoneOther'):
						return web.HTTPInternalServerError()
			if contact_property == 'ContactWebSite':
				assert ctc_ab is not None
				contact_websites = contact_info.findall('.//{*}webSites/{*}ContactWebSite')
				for contact_website in contact_websites:
					if str(find_element(contact_website, 'contactWebSiteType')) not in ('ContactWebSitePersonal','ContactWebSiteBusiness'):
						return web.HTTPInternalServerError()
			if contact_property == 'Annotation':
				if find_element(contact_info, 'contactType') != 'Me':
					if ctc_ab is None:
						return web.HTTPInternalServerError()
				annotations = contact_info.findall('.//{*}annotations/{*}Annotation')
				for annotation in annotations:
					name = find_element(annotation, 'Name')
					if name not in _ANNOTATION_NAMES:
						return web.HTTPInternalServerError()
					value = find_element(annotation, 'Value')
					value = bool_to_str(value) if isinstance(value, bool) else str(find_element(annotation, 'Value'))
					
					if name == 'MSN.IM.GTC':
						try:
							if value == '':
								gtc = GTCAnnotation.Empty
							else:
								gtc = GTCAnnotation(int(value))
						except ValueError:
							return web.HTTPInternalServerError()
					if name == 'MSN.IM.BLP':
						try:
							if value == '':
								blp = BLPAnnotation.Empty
							else:
								blp = BLPAnnotation(int(value))
						except ValueError:
							return web.HTTPInternalServerError()
			# TODO: Contact details
		if find_element(contact_info, 'contactType') != 'Me':
			if ctc_ab is None:
				return web.HTTPInternalServerError()
	for contact in contacts:
		updated = False
		contact_info = find_element(contact, 'contactInfo')
		if find_element(contact_info, 'contactType') == 'Me':
			contact_uuid = user.uuid
		else:
			contact_uuid = find_element(contact, 'contactId')
		if contact_uuid is not user.uuid and contact_uuid is not None:
			ctc_ab = backend.user_service.ab_get_entry_by_uuid(contact_uuid, user)
		properties_changed = str(contact.find('./{*}propertiesChanged')).strip().split(' ')
		
		for contact_property in properties_changed:
			if contact_property == 'ContactFirstName':
				assert ctc_ab is not None
				property = find_element(contact_info, 'firstName')
				ctc_ab.first_name = property
				print('First name:', property)
				updated = True
			if contact_property == 'ContactLastName':
				assert ctc_ab is not None
				property = find_element(contact_info, 'lastName')
				ctc_ab.last_name = property
				print('Last name:', property)
				updated = True
			if contact_property == 'MiddleName':
				assert ctc_ab is not None
				property = find_element(contact_info, 'MiddleName')
				ctc_ab.middle_name = property
				print('Middle name:', property)
				updated = True
			if contact_property == 'Anniversary':
				assert ctc_ab is not None
				property = find_element(contact_info, 'Anniversary')
				# When `Anniversary` node isn't present, lxml returns `-1` instead of None. What gives?
				if property not in (None,-1):
					property = str(property)
					property = datetime.strptime(property, '%Y/%m/%d')
				if property is -1:
					property = None
				ctc_ab.anniversary = property
				updated = True
			if contact_property == 'ContactBirthDate':
				assert ctc_ab is not None
				property = find_element(contact_info, 'birthdate')
				if property is not None:
					property = str(property)
					if property != '0001-01-01T00:00:00':
						property = iso_parser.parse(property)
					else:
						property = None
				ctc_ab.birthdate = property
				updated = True
			if contact_property == 'Comment':
				assert ctc_ab is not None
				property = find_element(contact_info, 'comment')
				if property is not None:
					property = str(property)
				ctc_ab.notes = property
				updated = True
			if contact_property == 'ContactLocation':
				assert ctc_ab is not None
				contact_locations = contact_info.findall('.//{*}locations/{*}ContactLocation')
				for contact_location in contact_locations:
					contact_location_type = str(find_element(contact_location, 'contactLocationType'))
					location_properties_changed = str(find_element(contact_location, 'Changes')).strip().split(' ')
					if contact_location_type not in ctc_ab.locations:
						ctc_ab.locations[contact_location_type] = models.AddressBookContactLocation(contact_location_type)
					for location_property in location_properties_changed:
						if location_property == 'Name':
							property = find_element(contact_location, 'name')
							if property is not None:
								property = str(property)
							ctc_ab.locations[contact_location_type].name = property
							updated = True
						if location_property == 'Street':
							property = find_element(contact_location, 'street')
							if property is not None:
								property = str(property)
							ctc_ab.locations[contact_location_type].street = property
							updated = True
						if location_property == 'City':
							property = find_element(contact_location, 'city')
							if property is not None:
								property = str(property)
							ctc_ab.locations[contact_location_type].city = property
							updated = True
						if location_property == 'State':
							property = find_element(contact_location, 'state')
							if property is not None:
								property = str(property)
							ctc_ab.locations[contact_location_type].state = property
							updated = True
						if location_property == 'Country':
							property = find_element(contact_location, 'country')
							if property is not None:
								property = str(property)
							ctc_ab.locations[contact_location_type].country = property
							updated = True
						if location_property == 'PostalCode':
							property = find_element(contact_location, 'postalCode')
							if property is not None:
								property = str(property)
							ctc_ab.locations[contact_location_type].zip_code = property
							updated = True
					if ctc_ab.locations[contact_location_type].street is None and ctc_ab.locations[contact_location_type].city is None and ctc_ab.locations[contact_location_type].state is None and ctc_ab.locations[contact_location_type].country is None and ctc_ab.locations[contact_location_type].zip_code is None:
						del ctc_ab.locations[contact_location_type]
						updated = True
			if contact_property == 'DisplayName':
				assert ctc_ab is not None
				property = find_element(contact_info, 'displayName')
				if property is not None:
					property = str(property)
				ctc_ab.name = property
				updated = True
			if contact_property == 'IsMessengerUser':
				assert ctc_ab is not None
				property = find_element(contact_info, 'isMessengerUser')
				ctc_ab.is_messenger_user = property
				updated = True
			if contact_property == 'ContactEmail':
				assert ctc_ab is not None
				contact_emails = contact_info.findall('.//{*}emails/{*}ContactEmail')
				for contact_email in contact_emails:
					email_properties_changed = str(find_element(contact_email, 'propertiesChanged')).strip().split(' ')
					for email_property in email_properties_changed:
						if email_property == 'Email':
							email = contact_email.find('./{*}email')
							if email is not None:
								email = str(email)
							if find_element(contact_email, 'contactEmailType') == 'ContactEmailPersonal':
								ctc_ab.personal_email = email
							if find_element(contact_email, 'contactEmailType') == 'ContactEmailBusiness':
								ctc_ab.work_email = email
							if find_element(contact_email, 'contactEmailType') == 'ContactEmailMessenger':
								ctc_ab.im_email = email
							if find_element(contact_email, 'contactEmailType') == 'ContactEmailOther':
								ctc_ab.other_email = email
							updated = True
			if contact_property == 'ContactPrimaryEmailType':
				assert ctc_ab is not None
				email_primary_type = str(find_element(contact_info, 'primaryEmailType'))
				ctc_ab.primary_email_type = email_primary_type
				updated = True
			if contact_property == 'ContactPhone':
				assert ctc_ab is not None
				contact_phones = contact_info.findall('.//{*}phones/{*}ContactPhone')
				for contact_phone in contact_phones:
					phone_properties_changed = str(find_element(contact_phone, 'propertiesChanged')).strip().split(' ')
					for phone_property in phone_properties_changed:
						if phone_property == 'Number':
							phone_number = contact_phone.find('./{*}number')
							if phone_number is not None:
								phone_number = str(phone_number)
							if find_element(contact_phone, 'contactPhoneType') == 'ContactPhonePersonal':
								ctc_ab.home_phone = phone_number
							if find_element(contact_phone, 'contactPhoneType') == 'ContactPhoneBusiness':
								ctc_ab.work_phone = phone_number
							if find_element(contact_phone, 'contactPhoneType') == 'ContactPhoneFax':
								ctc_ab.fax_phone = phone_number
							if find_element(contact_phone, 'contactPhoneType') == 'ContactPhonePager':
								ctc_ab.pager_phone = phone_number
							if find_element(contact_phone, 'contactPhoneType') == 'ContactPhoneMobile':
								ctc_ab.mobile_phone = phone_number
							if find_element(contact_phone, 'contactPhoneType') == 'ContactPhoneOther':
								ctc_ab.other_phone = phone_number
							updated = True
			if contact_property == 'ContactWebSite':
				assert ctc_ab is not None
				contact_websites = contact_info.findall('.//{*}webSites/{*}ContactWebSite')
				for contact_website in contact_websites:
					contact_website_type = str(find_element(contact_website, 'contactWebSiteType'))
					website = str(find_element(contact_website, 'webURL'))
					if contact_website_type == 'ContactWebSitePersonal':
						ctc_ab.personal_website = website
					if contact_website_type == 'ContactWebSiteBusiness':
						ctc_ab.business_website = website
					updated = True
			if contact_property == 'Annotation':
				if contact_uuid is not None:
					if find_element(contact_info, 'contactType') != 'Me':
						ctc_ab = backend.user_service.ab_get_entry_by_uuid(contact_uuid, user)
						if not ctc_ab:
							continue
				else:
					continue
				annotations = contact_info.findall('.//{*}annotations/{*}Annotation')
				for annotation in annotations:
					name = find_element(annotation, 'Name')
					value = find_element(annotation, 'Value')
					value = bool_to_str(value) if isinstance(value, bool) else str(find_element(annotation, 'Value'))
					
					if name == 'MSN.IM.GTC':
						if value == '':
							gtc = GTCAnnotation.Empty
						else:
							gtc = GTCAnnotation(int(value))
						
						if find_element(contact_info, 'contactType') == 'Me':
							bs.me_update({ 'gtc': None if gtc is GTCAnnotation.Empty else gtc.name })
						continue
					if name == 'MSN.IM.BLP':
						if value == '':
							blp = BLPAnnotation.Empty
						else:
							blp = BLPAnnotation(int(value))
						
						if find_element(contact_info, 'contactType') == 'Me':
							bs.me_update({ 'blp': None if blp is BLPAnnotation.Empty else blp.name })
						continue
					if name == 'MSN.IM.MPOP':
						if find_element(contact_info, 'contactType') == 'Me':
							bs.me_update({ 'mpop': None if value in ('', None) else value })
						continue
					if name == 'MSN.IM.RoamLiveProperties':
						if find_element(contact_info, 'contactType') == 'Me':
							bs.me_update({ 'rlp': value })
						continue
					if name == 'AB.NickName':
						if ctc_ab:
							ctc_ab.nickname = value
							updated = True
						continue
					if name == 'Live.Profile.Expression.LastChanged':
						# TODO: What's this used for?
						continue
					if ctc_ab:
						if ctc_ab.annotations is None:
							ctc_ab.annotations = {}
						ctc_ab.annotations.update({name: value})
						if value == '':
							del ctc_ab.annotations[name]
				updated = True
			# TODO: Contact details
		if find_element(contact_info, 'contactType') != 'Me' and updated:
			if ctc_ab is not None:
				contacts_to_update.append(ctc_ab)
	if contacts_to_update:
		bs.me_ab_contact_edit(contacts_to_update)
	
	return render(req, 'msn:abservice/ABContactUpdateResponse.xml', {
		'cachekey': _make_cache_key(),
		'host': settings.LOGIN_HOST,
		'session_id': util.misc.gen_uuid(),
	})

def ab_ABGroupAdd(req: web.Request, header: Any, action: Any, bs: BackendSession) -> web.Response:
	user = bs.user
	detail = user.detail
	assert detail is not None
	
	backend: Backend = req.app['backend']
	
	ab_id = find_element(action, 'abId')
	if ab_id is not None:
		ab_id = str(ab_id)
	else:
		ab_id = '00000000-0000-0000-0000-000000000000'
	
	if ab_id != '00000000-0000-0000-0000-000000000000':
		return web.HTTPInternalServerError()
	
	name = find_element(action, 'name')
	is_favorite = find_element(action, 'IsFavorite')
	
	if name == '(No Group)':
		return render(req, 'msn:abservice/Fault.groupalreadyexists.xml', {
			'action_str': 'ABGroupAdd',
		}, status = 500)
	
	if len(name) > MAX_GROUP_NAME_LENGTH:
		return render(req, 'msn:abservice/Fault.groupnametoolong.xml', {
			'action_str': 'ABGroupAdd',
		}, status = 500)
	
	if detail.get_groups_by_name(name) is not None:
		return render(req, 'msn:abservice/Fault.groupalreadyexists.xml', {
			'action_str': 'ABGroupAdd',
		}, status = 500)
	
	group = bs.me_group_add(name)
	return render(req, 'msn:abservice/ABGroupAddResponse.xml', {
		'cachekey': _make_cache_key(),
		'host': settings.LOGIN_HOST,
		'session_id': util.misc.gen_uuid(),
		'group_id': group.uuid,
	})

def ab_ABGroupUpdate(req: web.Request, header: Any, action: Any, bs: BackendSession) -> web.Response:
	user = bs.user
	detail = user.detail
	assert detail is not None
	
	backend: Backend = req.app['backend']
	
	ab_id = find_element(action, 'abId')
	if ab_id is not None:
		ab_id = str(ab_id)
	else:
		ab_id = '00000000-0000-0000-0000-000000000000'
	
	if ab_id != '00000000-0000-0000-0000-000000000000':
		return web.HTTPInternalServerError()
	
	groups = action.findall('.//{*}groups/{*}Group')
	for group_elm in groups:
		group_id = str(find_element(group_elm, 'groupId'))
		if group_id not in detail._groups_by_uuid:
			return web.HTTPInternalServerError()
		group_info = group_elm.find('.//{*}groupInfo')
		properties_changed = find_element(group_elm, 'propertiesChanged')
		if not properties_changed:
			return web.HTTPInternalServerError()
		properties_changed = str(properties_changed).strip().split(' ')
		for i, contact_property in enumerate(properties_changed):
			if contact_property not in _CONTACT_PROPERTIES:
				return web.HTTPInternalServerError()
		for contact_property in properties_changed:
			if contact_property == 'GroupName':
				name = str(find_element(group_info, 'name'))
				if name is None:
					return web.HTTPInternalServerError()
				elif name == '(No Group)':
					return render(req, 'msn:abservice/Fault.groupalreadyexists.xml', {
						'action_str': 'ABGroupUpdate',
					}, status = 500)
				elif len(name) > MAX_GROUP_NAME_LENGTH:
					return render(req, 'msn:abservice/Fault.groupnametoolong.xml', {
						'action_str': 'ABGroupUpdate',
					}, status = 500)
				
				if detail.get_groups_by_name(name) is not None:
					return render(req, 'msn:abservice/Fault.groupalreadyexists.xml', {
						'action_str': 'ABGroupUpdate',
					}, status = 500)
			is_favorite = find_element(group_info, 'IsFavorite')
			if is_favorite is not None:
				if not isinstance(is_favorite, bool):
					return web.HTTPInternalServerError()
	for group_elm in groups:
		group_id = str(find_element(group_elm, 'groupId'))
		g = detail.get_group_by_id(group_id)
		group_info = group_elm.find('.//{*}groupInfo')
		properties_changed = find_element(group_elm, 'propertiesChanged')
		properties_changed = str(properties_changed).strip().split(' ')
		for contact_property in properties_changed:
			if contact_property == 'GroupName':
				name = str(find_element(group_info, 'name'))
				bs.me_group_edit(group_id, new_name = name)
			# What's the `propertiesChanged` value for the favourite setting? Check for the node for now
			is_favorite = find_element(group_info, 'IsFavorite')
			if is_favorite is not None:
				bs.me_group_edit(group_id, is_favorite = is_favorite)
	return render(req, 'msn:abservice/ABGroupUpdateResponse.xml', {
		'cachekey': _make_cache_key(),
		'host': settings.LOGIN_HOST,
		'session_id': util.misc.gen_uuid(),
	})

def ab_ABGroupDelete(req: web.Request, header: Any, action: Any, bs: BackendSession) -> web.Response:
	user = bs.user
	detail = user.detail
	assert detail is not None
	
	backend: Backend = req.app['backend']
	
	ab_id = find_element(action, 'abId')
	if ab_id is not None:
		ab_id = str(ab_id)
	else:
		ab_id = '00000000-0000-0000-0000-000000000000'
	
	if ab_id != '00000000-0000-0000-0000-000000000000':
		return web.HTTPInternalServerError()
	
	group_ids = [str(group_id) for group_id in action.findall('.//{*}groupFilter/{*}groupIds/{*}guid')]
	for group_id in group_ids:
		if group_id not in detail._groups_by_uuid:
			return web.HTTPInternalServerError()
	for group_id in group_ids:
		bs.me_group_remove(group_id)
	return render(req, 'msn:abservice/ABGroupDeleteResponse.xml', {
		'cachekey': _make_cache_key(),
		'host': settings.LOGIN_HOST,
		'session_id': util.misc.gen_uuid(),
	})

def ab_ABGroupContactAdd(req: web.Request, header: Any, action: Any, bs: BackendSession) -> web.Response:
	user = bs.user
	detail = user.detail
	assert detail is not None
	
	backend: Backend = req.app['backend']
	
	ab_id = find_element(action, 'abId')
	if ab_id is not None:
		ab_id = str(ab_id)
	else:
		ab_id = '00000000-0000-0000-0000-000000000000'
	
	if ab_id != '00000000-0000-0000-0000-000000000000':
		return web.HTTPInternalServerError()
	
	group_ids = [str(group_id) for group_id in action.findall('.//{*}groupFilter/{*}groupIds/{*}guid')]
	
	for group_id in group_ids:
		if group_id not in detail._groups_by_uuid:
			return web.HTTPInternalServerError()
	
	if find_element(action, 'contactInfo') is not None:
		email = find_element(action, 'passportName')
		if email is None:
			email = find_element(action, 'email')
			if email is None:
				return web.HTTPInternalServerError()
		type = find_element(action, 'contactType') or 'Regular'
		contact_uuid = backend.util_get_uuid_from_email(email)
		assert contact_uuid is not None
		
		ctc = detail.contacts.get(contact_uuid)
		if ctc is not None and ctc.lists & models.Lst.FL:
			for group_id in group_ids:
				for group_contact_entry in ctc._groups:
					if group_contact_entry.group_uuid == group_id:
						return web.HTTPInternalServerError()
		
		ctc_ab = backend.user_service.ab_get_entry_by_email(email, ('Regular' if type == 'LivePending' else type), user)
		
		if ctc_ab is not None:
			for group_id in group_ids:
				if group_id in ctc_ab.groups:
					return web.HTTPInternalServerError()
		
		is_messenger_user = find_element(action, 'isMessengerUser') or False
		
		for group_id in group_ids:
			try:
				ctc, _ = bs.me_contact_add(contact_uuid, models.Lst.FL, group_id = group_id, name = email)
			except:
				return web.HTTPInternalServerError()
		
		if ctc_ab is None:
			assert ctc is not None
			ctc_ab = models.AddressBookContact(
				('Regular' if type == 'LivePending' else type), backend.user_service.gen_ab_entry_id(user), util.misc.gen_uuid(), ctc.head.email, ctc.status.name, set(),
				member_uuid = contact_uuid, is_messenger_user = is_messenger_user,
			)
		
		for group_id in group_ids:
			ctc_ab.groups.add(group_id)
	else:
		contact_uuid = find_element(action, 'contactId')
		assert contact_uuid is not None
		ctc_ab = backend.user_service.ab_get_entry_by_uuid(contact_uuid, user)
		if ctc_ab is None:
			return web.HTTPInternalServerError()
		
		for group_id in group_ids:
			if group_id in ctc_ab.groups:
				return web.HTTPInternalServerError()
		
		ctc = detail.contacts.get(ctc_ab.member_uuid or '')
		if ctc is None or not ctc.lists & models.Lst.FL:
			return web.HTTPInternalServerError()
		
		for group_id in group_ids:
			for group_contact_entry in ctc._groups:
				if group_contact_entry.group_uuid == group_id:
					return web.HTTPInternalServerError()
		
		for group_id in group_ids:
			bs.me_group_contact_add(group_id, ctc.head.uuid)
			ctc_ab.groups.add(group_id)
	return render(req, 'msn:abservice/ABGroupContactAddResponse.xml', {
		'cachekey': _make_cache_key(),
		'host': settings.LOGIN_HOST,
		'session_id': util.misc.gen_uuid(),
		'contact_uuid': contact_uuid,
	})

def ab_ABGroupContactDelete(req: web.Request, header: Any, action: Any, bs: BackendSession) -> web.Response:
	user = bs.user
	detail = user.detail
	assert detail is not None
	
	backend: Backend = req.app['backend']
	
	ab_id = find_element(action, 'abId')
	if ab_id is not None:
		ab_id = str(ab_id)
	else:
		ab_id = '00000000-0000-0000-0000-000000000000'
	
	if ab_id != '00000000-0000-0000-0000-000000000000':
		return web.HTTPInternalServerError()
	
	group_ids = [str(group_id) for group_id in action.findall('.//{*}groupFilter/{*}groupIds/{*}guid')]
	
	for group_id in group_ids:
		if group_id not in detail._groups_by_uuid:
			return web.HTTPInternalServerError()
	
	contact_uuid = find_element(action, 'contactId')
	assert contact_uuid is not None
	ctc_ab = backend.user_service.ab_get_entry_by_uuid(contact_uuid, user)
	if ctc_ab is None:
		return web.HTTPInternalServerError()
	else:
		for group_id in group_ids:
			if group_id not in ctc_ab.groups:
				return web.HTTPInternalServerError()
	
	ctc = detail.contacts.get(ctc_ab.member_uuid or '')
	if ctc is not None:
		if ctc.lists & models.Lst.FL:
			for group_id in group_ids:
				ctc_in_group = False
				for group_contact_entry in ctc._groups:
					if group_contact_entry.group_uuid == group_id:
						ctc_in_group = True
						break
				if not ctc_in_group:
					return web.HTTPInternalServerError()
			for group_id in group_ids:
				bs.me_group_contact_remove(group_id, ctc.head.uuid)
				ctc_ab.groups.remove(group_id)
	
	return render(req, 'msn:abservice/ABGroupContactDeleteResponse.xml', {
		'cachekey': _make_cache_key(),
		'host': settings.LOGIN_HOST,
		'session_id': util.misc.gen_uuid(),
	})

def ab_CreateCircle(req: web.Request, header: Any, action: Any, bs: BackendSession) -> web.Response:
	return render(req, 'msn:abservice/Fault.circlenolongersupported.xml', status = 500)
	
	'''
	user = bs.user
	
	if find_element(action, 'Domain') == 1 and find_element(action, 'HostedDomain') == 'live.com' and find_element(action, 'Type') == 2 and isinstance(find_element(action, 'IsPresenceEnabled'), bool):
		membership_access = int(find_element(action, 'MembershipAccess'))
		request_membership_option = int(find_element(action, 'RequestMembershipOption'))
		
		circle_name = str(find_element(action, 'DisplayName'))
		circle_owner_friendly = str(find_element(action, 'PublicDisplayName'))
		
		circle_id, circle_acc_uuid = backend.user_service.msn_create_circle(user.uuid, circle_name, circle_owner_friendly, membership_access, request_membership_option, find_element(action, 'IsPresenceEnabled'))
		if circle_id is None:
			return web.HTTPInternalServerError()
		
		bs.me_subscribe_ab(circle_id)
		# Add circle relay to contact list
		bs.me_contact_add(circle_acc_uuid, models.Lst.FL, add_to_ab = False)
		bs.me_contact_add(circle_acc_uuid, models.Lst.AL)
		
		# Add self to individual AB
		# TODO: Proper hidden representative of circle creator (does this display them in the roster?)
		#ctc_self_hidden_representative = models.AddressBookContact(
		#	'Circle', backend.user_service.gen_ab_entry_id(user), util.misc.gen_uuid(), user.email, user.status.name or user.email, set(), {
		#		models.NetworkID.WINDOWS_LIVE: models.NetworkInfo(
		#			models.NetworkID.WINDOWS_LIVE, 'WL', user.email,
		#			user.status.name, models.RelationshipInfo(
		#				models.ABRelationshipType.Circle, models.ABRelationshipRole.Admin, models.ABRelationshipState.Accepted,
		#			),
		#		)
		#	},
		#	member_uuid = user.uuid, is_messenger_user = True,
		#)
		#await backend.user_service.mark_ab_modified_async('00000000-0000-0000-0000-000000000000', { 'contacts': [ctc_self_hidden_representative], }, user)
		backend.user_service.msn_update_circleticket(user.uuid, cid_format(user.uuid, decimal = True))
		
		try:
			return render(req, 'msn:abservice/CreateCircleResponse.xml', {
				'cachekey': _make_cache_key(),
				'host': settings.LOGIN_HOST,
				'session_id': util.misc.gen_uuid(),
				'circle_id': circle_id,
			})
		finally:
			_, _, _, ab_last_modified, _ = backend.user_service.get_ab_contents(circle_id, user)
			bs.evt.msn_on_notify_ab(cid_format(user.uuid, decimal = True), util.misc.date_format(ab_last_modified))
			
			#circle_bs = backend.login(backend.util_get_uuid_from_email('{}@live.com'.format(circle_id), models.NetworkID.CIRCLE), None, CircleBackendEventHandler(), only_once = True)
			#if circle_bs is not None:
			#	if bs.front_data.get('msn_circle_sessions') is None:
			#		bs.front_data['msn_circle_sessions'] = { circle_bs }
			#	else:
			#		bs.front_data['msn_circle_sessions'].add(circle_bs)
			#	circle_bs.front_data['msn_circle_roster'] = { bs }
			#	circle_bs.me_update({ 'substatus': models.Substatus.Online })
	'''

def ab_ManageWLConnection(req: web.Request, header: Any, action: Any, bs: BackendSession) -> web.Response:
	# TODO: Finish `NetworkInfo` implementation for circles
	raise NotImplementedError()
	'''
	ab_id = find_element(action, 'ABId')
	if ab_id is not None:
		ab_id = str(ab_id)
	else:
		ab_id = '00000000-0000-0000-0000-000000000000'
	
	if ab_id not in detail.subscribed_ab_stores:
		return web.HTTPInternalServerError()
	
	contact_uuid = find_element(action, 'contactId')
	assert contact_uuid is not None
	
	tpl = backend.user_service.get_ab_contents(user)
	assert tpl is not None
	user_creator, _, _, _ = tpl
	
	ctc_ab = backend.user_service.ab_get_entry_by_uuid(contact_uuid, user)
	
	if ctc_ab is None or ctc_ab.networkinfos.get(models.NetworkID.WINDOWS_LIVE) is not None:
		return web.HTTPInternalServerError()
	
	if find_element(action, 'connection') == True:
		try:
			relationship_type = models.ABRelationshipType(find_element(action, 'relationshipType'))
			relationship_role = find_element(action, 'relationshipRole')
			if relationship_role is not None:
				relationship_role = models.ABRelationshipRole(relationship_role)
			wl_action = int(find_element(action, 'action'))
		except ValueError:
			return web.HTTPInternalServerError()
		
		if not ctc_ab.member_uuid:
			return web.HTTPInternalServerError()
		ctc_head = backend._load_user_record(ctc_ab.member_uuid)
		if ctc_head is None:
			return web.HTTPInternalServerError()
		
		tpl = backend.user_service.get_ab_contents(ctc_head)
		assert tpl is not None
		_, ctc_creator_ab, _, ctc_ab_last_modified, _ = tpl
		
		if wl_action == 1:
			if relationship_type == models.ABRelationshipType.Circle:
				#membership_set = backend.user_service.msn_circle_set_user_membership(ab_id, ctc.email, member_role = models.ABRelationshipRole.StatePendingOutbound, member_state = models.ABRelationshipState.Accepted)
				#if not membership_set:
				#	return web.HTTPInternalServerError()
				return web.HTTPInternalServerError()
			
			if relationship_role != None:
				return web.HTTPInternalServerError()
			
			ctc_ab.networkinfos[models.NetworkID.WINDOWS_LIVE] = models.NetworkInfo(
				models.NetworkID.WINDOWS_LIVE, 'WL', ctc_ab.email,
				ctc_ab.name or ctc_ab.email, models.RelationshipInfo(
					relationship_type, models.ABRelationshipRole.Empty, models.ABRelationshipState.WaitingResponse,
				),
			)
			
			ctc_ab_contact = backend.user_service.ab_get_entry_by_email(user.email, ('Circle' if ab_id.startswith('00000000-0000-0000-0009') else 'LivePending'), ctc_head)
			if not ctc_ab_contact and not ab_id.startswith('00000000-0000-0000-0009'):
				ctc_ab_contact = backend.user_service.ab_get_entry_by_email(user.email, 'Live', ctc_head)
			if ctc_ab_contact:
				return web.HTTPInternalServerError()
			ctc_ab_contact = models.AddressBookContact(
				('Circle' if ab_id.startswith('00000000-0000-0000-0009') else 'LivePending'), backend.user_service.gen_ab_entry_id(user), util.misc.gen_uuid(), user.email, user.status.name or user.email, set(),
				networkinfos = {
					models.NetworkID.WINDOWS_LIVE: models.NetworkInfo(
						models.NetworkID.WINDOWS_LIVE, 'WL', user.email,
						user.status.name, models.RelationshipInfo(
							relationship_type, models.ABRelationshipRole.Empty, models.ABRelationshipState.WaitingResponse,
						),
					),
				}, member_uuid = user.uuid, is_messenger_user = True,
			)
			
			await backend.user_service.mark_ab_modified_async({ 'contacts': [ctc_ab] }, user)
			await backend.user_service.mark_ab_modified_async({ 'contacts': [ctc_ab_contact] }, ctc_head)
			
			for ctc_sess in backend.util_get_sessions_by_user(ctc_head):
				ctc_sess.evt.msn_on_notify_ab(cid_format(user_creator.uuid), str(util.misc.date_format(ctc_ab_last_modified or datetime.utcnow())))
	
	return render(req, 'msn:abservice/ManageWLConnection/ManageWLConnection.xml', {
		'cachekey': _make_cache_key(),
		'host': settings.LOGIN_HOST,
		'session_id': util.misc.gen_uuid(),
		'ab_id': ab_id,
		'contact': ctc_ab,
		'user_creator_detail': user_creator.detail,
	})
	'''

def ab_FindFriendsInCommon(req: web.Request, header: Any, action: Any, bs: BackendSession) -> web.Response:
	raise NotImplementedError()
	# Count the number of `Live` contacts from the target contact and compare then with the caller's contacts to see if both have the same contacts
	'''
	ctc_head = None
	matched_ab_ctcs = []
	
	ab_id = find_element(action, 'ABId')
	if ab_id is not None:
		ab_id = str(ab_id)
	else:
		ab_id = '00000000-0000-0000-0000-000000000000'
	
	if ab_id not in detail.subscribed_ab_stores:
		return web.HTTPInternalServerError()
	
	try:
		domain_id = models.NetworkID(find_element(action, 'domainID'))
	except ValueError:
		return web.HTTPInternalServerError()
	
	cid = str(find_element(action, 'Cid'))
	
	tpl = backend.user_service.get_ab_contents(user)
	assert tpl is not None
	_, _, _, ab_contacts = tpl
	
	for ab_contact in ab_contacts.values():
		if ab_contact.member_uuid is None: continue
		
		if cid_format(ab_contact.member_uuid) == cid and ab_contact.type == 'Live' and ab_contact.networkinfos.get(domain_id) is not None:
			ctc_head = backend._load_user_record(ab_contact.member_uuid)
	
	if ctc_head is None:
		return web.HTTPInternalServerError()
	
	tpl = backend.user_service.get_ab_contents(ctc_head)
	assert tpl is not None
	_, _, _, ctc_ab_contacts = tpl
	
	for ctc_ab_ctc in ctc_ab_contacts:
		if ctc_ab_ctc.type != 'Live': continue
		
		for ab_ctc in ab_contacts:
			if ab_ctc.email == ctc_ab_ctc.email and ab_ctc.type == 'Live':
				matched_ab_ctcs.append(ab_ctc)
	
	# TODO: Response is a list of matched and unmatched `Contact`'s, but exactly what to add in the `Contact` nodes
	'''

def ab_UpdateDynamicItem(req: web.Request, header: Any, action: Any, bs: BackendSession) -> web.Response:
	# TODO: UpdateDynamicItem
	return unknown_soap(req, header, action, expected = True)

def _get_ab_contents(user: models.User) -> Tuple[datetime, datetime, List[models.Contact]]:
	detail = user.detail
	assert detail is not None
	return user.date_created, user.date_modified, list(detail.contacts.values())

_CONTACT_PROPERTIES = (
	'Comment', 'DisplayName', 'ContactType', 'ContactFirstName', 'ContactLastName', 'MiddleName', 'Anniversary', 'ContactBirthDate', 'ContactEmail', 'ContactLocation', 'ContactWebSite', 'ContactPrimaryEmailType', 'ContactPhone', 'GroupName',
	'IsMessengerEnabled', 'IsMessengerUser', 'IsFavorite', 'HasSpace',
	'Annotation', 'Capability', 'MessengerMemberInfo',
)

_CONTACT_PHONE_PROPERTIES = (
	'Number',
)

_CONTACT_EMAIL_PROPERTIES = (
	'Email',
)

_CONTACT_LOCATION_PROPERTIES = (
	'Name', 'Street', 'City', 'State', 'Country', 'PostalCode',
)

_ANNOTATION_NAMES = (
	'MSN.IM.InviteMessage', 'MSN.IM.MPOP', 'MSN.IM.BLP', 'MSN.IM.GTC', 'MSN.IM.RoamLiveProperties',
	'MSN.IM.MBEA', 'MSN.IM.BuddyType', 'AB.NickName', 'AB.Profession', 'AB.Spouse', 'AB.JobTitle', 'Live.Locale', 'Live.Profile.Expression.LastChanged',
	'Live.Passport.Birthdate', 'Live.Favorite.Order',
)

class GTCAnnotation(IntEnum):
	Empty = 0
	A = 1
	N = 2

class BLPAnnotation(IntEnum):
	Empty = 0
	AL = 1
	BL = 2

def _make_now_str() -> str:
	s = util.misc.date_format(datetime.utcnow())
	assert s is not None
	return s

def _make_cache_key() -> str:
	return secrets.token_urlsafe(172)
