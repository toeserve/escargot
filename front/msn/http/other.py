from typing import Optional, Any, Dict, Tuple, List
from datetime import datetime, timedelta
from email.parser import Parser
from email.header import decode_header
from urllib.parse import unquote
from pathlib import Path
import re
import secrets
import base64
import json
import time
from markupsafe import Markup
from aiohttp import web

import settings
from core import models, event
from core.backend import Backend, BackendSession, MAX_GROUP_NAME_LENGTH
from ..misc import gen_mail_data, format_oim, cid_format
import util.misc
from .util import find_element, get_tag_localname, render, preprocess_soap, unknown_soap, bool_to_str

LOGIN_PATH = '/login'
TMPL_DIR = 'front/msn/tmpl'
ETC_DIR = 'front/msn/etc'
PP = 'Passport1.4 '

def register(app: web.Application) -> None:
	util.misc.add_to_jinja_env(app, 'msn', TMPL_DIR, globals = {
		'date_format': util.misc.date_format,
		'cid_format': cid_format,
		'bool_to_str': bool_to_str,
		'contact_is_favorite': _contact_is_favorite,
		'datetime': datetime,
	})
	
	# MSN >= 5
	app.router.add_get('/nexus-mock', handle_nexus)
	app.router.add_get('/rdr/pprdr.asp', handle_nexus)
	app.router.add_get(LOGIN_PATH, handle_login)
	
	# MSN >= 6
	app.router.add_get('/etc/MsgrConfig', handle_msgrconfig)
	app.router.add_post('/etc/MsgrConfig', handle_msgrconfig)
	app.router.add_get('/Config/MsgrConfig.asmx', handle_msgrconfig)
	app.router.add_post('/Config/MsgrConfig.asmx', handle_msgrconfig)
	app.router.add_get('/config/MsgrConfig.asmx', handle_msgrconfig)
	app.router.add_post('/config/MsgrConfig.asmx', handle_msgrconfig)
	app.router.add_get('/etc/text-ad-service', handle_textad)
	
	# MSN >= 7.5
	app.router.add_route('OPTIONS', '/NotRST.srf', handle_not_rst)
	app.router.add_post('/NotRST.srf', handle_not_rst)
	app.router.add_post('/RST.srf', handle_rst)
	app.router.add_post('/RST2.srf', lambda req: handle_rst(req, rst2 = True))
	
	# MSN 8.1.0178
	app.router.add_post('/storageservice/SchematizedStore.asmx', handle_storageservice)
	app.router.add_get('/storage/usertile/{uuid}/static', handle_usertile)
	app.router.add_get('/storage/usertile/{uuid}/small', lambda req: handle_usertile(req, small = True))
	app.router.add_post('/rsi/rsi.asmx', handle_rsi)
	app.router.add_post('/OimWS/oim.asmx', handle_oim)
	
	# Misc
	app.router.add_get('/etc/debug', handle_debug)

async def handle_storageservice(req: web.Request) -> web.Response:
	header, action, bs, token = await preprocess_soap(req)
	assert bs is not None
	action_str = get_tag_localname(action)
	now_str = util.misc.date_format(datetime.utcnow())
	timestamp = int(time.time())
	user = bs.user
	cachekey = secrets.token_urlsafe(172)
	
	cid = cid_format(user.uuid)
	
	if action_str == 'GetProfile':
		return render(req, 'msn:storageservice/GetProfileResponse.xml', {
			'cachekey': cachekey,
			'cid': cid,
			'pptoken1': token,
			'user': user,
			'now': now_str,
			'timestamp': timestamp,
			'host': settings.STORAGE_HOST
		})
	if action_str == 'FindDocuments':
		# TODO: FindDocuments
		return render(req, 'msn:storageservice/FindDocumentsResponse.xml', {
			'cachekey': cachekey,
			'cid': cid,
			'pptoken1': token,
			'user': user,
		})
	if action_str == 'UpdateProfile':
		# TODO: UpdateProfile
		return render(req, 'msn:storageservice/UpdateProfileResponse.xml', {
			'cachekey': cachekey,
			'cid': cid,
			'pptoken1': token,
		})
	if action_str == 'DeleteRelationships':
		# TODO: DeleteRelationships
		return render(req, 'msn:storageservice/DeleteRelationshipsResponse.xml', {
			'cachekey': cachekey,
			'cid': cid,
			'pptoken1': token,
		})
	if action_str == 'CreateDocument':
		return handle_create_document(req, action, user, cid, token, timestamp)
	if action_str == 'CreateRelationships':
		# TODO: CreateRelationships
		return render(req, 'msn:storageservice/CreateRelationshipsResponse.xml', {
			'cachekey': cachekey,
			'cid': cid,
			'pptoken1': token,
		})
	if action_str in { 'ShareItem' }:
		# TODO: ShareItem
		return unknown_soap(req, header, action, expected = True)
	return unknown_soap(req, header, action)

async def handle_rsi(req: web.Request) -> web.Response:
	header, action, bs, token = await preprocess_soap_rsi(req)
	
	if token is None or bs is None:
		return render(req, 'msn:oim/Fault.validation.xml', status = 500)
	action_str = get_tag_localname(action)
	
	user = bs.user
	
	backend = req.app['backend']
	
	if action_str == 'GetMetadata':
		return render(req, 'msn:oim/GetMetadataResponse.xml', {
			'md': gen_mail_data(user, backend, on_ns = False, e_node = False),
		})
	if action_str == 'GetMessage':
		oim_uuid = find_element(action, 'messageId')
		oim_markAsRead = find_element(action, 'alsoMarkAsRead')
		oim = backend.user_service.get_oim_single(user, oim_uuid, mark_read = oim_markAsRead is True)
		return render(req, 'msn:oim/GetMessageResponse.xml', {
			'oim_data': format_oim(oim),
		})
	if action_str == 'DeleteMessages':
		messageIds = action.findall('.//{*}messageIds/{*}messageId')
		if not messageIds:
			return render(req, 'msn:oim/Fault.validation.xml', status = 500)
		for messageId in messageIds:
			if backend.user_service.get_oim_single(user, messageId) is None:
				return render(req, 'msn:oim/Fault.validation.xml', status = 500)
		for messageId in messageIds:
			backend.user_service.delete_oim(user.uuid, messageId)
		bs.evt.msn_on_oim_deletion(len(messageIds))
		return render(req, 'msn:oim/DeleteMessagesResponse.xml')
	
	return render(req, 'msn:Fault.unsupported.xml', { 'faultactor': action_str })

async def handle_oim(req: web.Request) -> web.Response:
	header, body_msgtype, body_content, bs, token = await preprocess_soap_oimws(req)
	soapaction = req.headers.get('SOAPAction').strip('"')
	
	lockkey_result = header.find('.//{*}Ticket').get('lockkey')
	
	if bs is None or lockkey_result in (None,''):
		return render(req, 'msn:oim/Fault.authfailed.xml', {
			'owsns': ('http://messenger.msn.com/ws/2004/09/oim/' if soapaction.startswith('http://messenger.msn.com/ws/2004/09/oim/') else 'http://messenger.live.com/ws/2006/09/oim/'),
		}, status = 500)
	
	backend: Backend = req.app['backend']
	user = bs.user
	detail = user.detail
	assert detail is not None
	
	friendlyname = None
	friendlyname_str = None
	friendly_charset = None
	
	friendlyname_mime = header.find('.//{*}From').get('friendlyName')
	email = header.find('.//{*}From').get('memberName')
	recipient = header.find('.//{*}To').get('memberName')
	
	recipient_uuid = backend.util_get_uuid_from_email(recipient)
	
	if email != user.email or recipient_uuid is None or not _is_on_al(recipient_uuid, backend, user, detail):
		return render(req, 'msn:oim/Fault.unavailable.xml', {
			'owsns': ('http://messenger.msn.com/ws/2004/09/oim/' if soapaction.startswith('http://messenger.msn.com/ws/2004/09/oim/') else 'http://messenger.live.com/ws/2006/09/oim/'),
		}, status = 500)
	
	assert req.transport is not None
	peername = req.transport.get_extra_info('peername')
	if peername:
		host = peername[0]
	else:
		host = '127.0.0.1'
	
	oim_msg_seq = str(find_element(header, 'Sequence/MessageNumber'))
	if not oim_msg_seq.isnumeric():
		return render(req, 'msn:oim/Fault.invalidcontent.xml', {
			'owsns': ('http://messenger.msn.com/ws/2004/09/oim/' if soapaction.startswith('http://messenger.msn.com/ws/2004/09/oim/') else 'http://messenger.live.com/ws/2006/09/oim/'),
		}, status = 500)
	
	if friendlyname_mime is not None:
		try:
			friendlyname, friendly_charset = decode_header(friendlyname_mime)[0]
		except:
			return render(req, 'msn:oim/Fault.invalidcontent.xml', {
				'owsns': ('http://messenger.msn.com/ws/2004/09/oim/' if soapaction.startswith('http://messenger.msn.com/ws/2004/09/oim/') else 'http://messenger.live.com/ws/2006/09/oim/'),
			}, status = 500)
	
	if friendly_charset is None:
		friendly_charset = 'utf-8'
	
	if friendlyname is not None:
		friendlyname_str = friendlyname.decode(friendly_charset)
	
	oim_proxy_string = header.find('.//{*}From').get('proxy')
	
	try:
		oim_mime = Parser().parsestr(body_content)
	except:
		return render(req, 'msn:oim/Fault.invalidcontent.xml', {
			'owsns': ('http://messenger.msn.com/ws/2004/09/oim/' if soapaction.startswith('http://messenger.msn.com/ws/2004/09/oim/') else 'http://messenger.live.com/ws/2006/09/oim/'),
		}, status = 500)
	
	oim_run_id = str(oim_mime.get('X-OIM-Run-Id'))
	if oim_run_id is None:
		return render(req, 'msn:oim/Fault.invalidcontent.xml', {
			'owsns': ('http://messenger.msn.com/ws/2004/09/oim/' if soapaction.startswith('http://messenger.msn.com/ws/2004/09/oim/') else 'http://messenger.live.com/ws/2006/09/oim/'),
		}, status = 500)
	if not re.match(r'^\{?[A-Fa-f0-9]{8,8}-([A-Fa-f0-9]{4,4}-){3,3}[A-Fa-f0-9]{12,12}\}?', oim_run_id):
		return render(req, 'msn:oim/Fault.invalidcontent.xml', {
			'owsns': ('http://messenger.msn.com/ws/2004/09/oim/' if soapaction.startswith('http://messenger.msn.com/ws/2004/09/oim/') else 'http://messenger.live.com/ws/2006/09/oim/'),
		}, status = 500)
	oim_run_id = oim_run_id.replace('{', '').replace('}', '')
	if ('X-Message-Info','Received','From','To','Subject','X-OIM-originatingSource','X-OIMProxy','Message-ID','X-OriginalArrivalTime','Date','Return-Path') in oim_mime.keys():
		return render(req, 'msn:oim/Fault.invalidcontent.xml', {
			'owsns': ('http://messenger.msn.com/ws/2004/09/oim/' if soapaction.startswith('http://messenger.msn.com/ws/2004/09/oim/') else 'http://messenger.live.com/ws/2006/09/oim/'),
		}, status = 500)
	if str(oim_mime.get('MIME-Version')) != '1.0':
		return render(req, 'msn:oim/Fault.invalidcontent.xml', {
			'owsns': ('http://messenger.msn.com/ws/2004/09/oim/' if soapaction.startswith('http://messenger.msn.com/ws/2004/09/oim/') else 'http://messenger.live.com/ws/2006/09/oim/'),
		}, status = 500)
	if not str(oim_mime.get('Content-Type')).startswith('text/plain'):
		return render(req, 'msn:oim/Fault.invalidcontent.xml', {
			'owsns': ('http://messenger.msn.com/ws/2004/09/oim/' if soapaction.startswith('http://messenger.msn.com/ws/2004/09/oim/') else 'http://messenger.live.com/ws/2006/09/oim/'),
		}, status = 500)
	if str(oim_mime.get('Content-Transfer-Encoding')) != 'base64':
		return render(req, 'msn:oim/Fault.invalidcontent.xml', {
			'owsns': ('http://messenger.msn.com/ws/2004/09/oim/' if soapaction.startswith('http://messenger.msn.com/ws/2004/09/oim/') else 'http://messenger.live.com/ws/2006/09/oim/'),
		}, status = 500)
	if str(oim_mime.get('X-OIM-Message-Type')) != 'OfflineMessage':
		return render(req, 'msn:oim/Fault.invalidcontent.xml', {
			'owsns': ('http://messenger.msn.com/ws/2004/09/oim/' if soapaction.startswith('http://messenger.msn.com/ws/2004/09/oim/') else 'http://messenger.live.com/ws/2006/09/oim/'),
		}, status = 500)
	oim_seq_num = str(oim_mime.get('X-OIM-Sequence-Num'))
	if oim_seq_num != oim_msg_seq:
		return render(req, 'msn:oim/Fault.invalidcontent.xml', {
			'owsns': ('http://messenger.msn.com/ws/2004/09/oim/' if soapaction.startswith('http://messenger.msn.com/ws/2004/09/oim/') else 'http://messenger.live.com/ws/2006/09/oim/'),
		}, status = 500)
	oim_headers = {name: str(value) for name, value in oim_mime.items()}
	
	try:
		i = body_content.index('\n\n') + 2
		oim_body = body_content[i:]
		for oim_b64_line in oim_body.split('\n'):
			if len(oim_b64_line) > 77:
				return render(req, 'msn:oim/Fault.invalidcontent.xml', {
					'owsns': ('http://messenger.msn.com/ws/2004/09/oim/' if soapaction.startswith('http://messenger.msn.com/ws/2004/09/oim/') else 'http://messenger.live.com/ws/2006/09/oim/'),
				}, status = 500)
		oim_body_normal = oim_body.strip()
		oim_body_normal = base64.b64decode(oim_body_normal).decode('utf-8')
		
		backend.user_service.save_oim(bs, recipient_uuid, oim_run_id, host, oim_body_normal, True, from_friendly = friendlyname_str, from_friendly_charset = friendly_charset, headers = oim_headers, oim_proxy = oim_proxy_string)
	except:
		return render(req, 'msn:oim/Fault.invalidcontent.xml', {
			'owsns': ('http://messenger.msn.com/ws/2004/09/oim/' if soapaction.startswith('http://messenger.msn.com/ws/2004/09/oim/') else 'http://messenger.live.com/ws/2006/09/oim/'),
		}, status = 500)
	
	return render(req, 'msn:oim/StoreResponse.xml', {
		'seq': oim_msg_seq,
		'owsns': ('http://messenger.msn.com/ws/2004/09/oim/' if soapaction.startswith('http://messenger.msn.com/ws/2004/09/oim/') else 'http://messenger.live.com/ws/2006/09/oim/'),
	})

def _is_on_al(uuid: str, backend: Backend, user: models.User, detail: models.UserDetail) -> bool:
	contact = detail.contacts.get(uuid)
	if user.settings.get('BLP', 'AL') == 'AL' and (contact is None or not contact.lists & models.Lst.BL):
		return True
	if user.settings.get('BLP', 'AL') == 'BL' and contact is not None and not contact.lists & models.Lst.BL:
		return True
	
	if contact is not None:
		ctc_detail = backend._load_detail(contact.head)
		assert ctc_detail is not None
		
		ctc_me = ctc_detail.contacts.get(user.uuid)
		if ctc_me is None and contact.head.settings.get('BLP', 'AL') == 'AL':
			return True
		if ctc_me is not None and not ctc_me.lists & models.Lst.BL:
			return True
	return False

async def preprocess_soap_rsi(req: web.Request) -> Tuple[Any, Any, Optional[BackendSession], str]:
	from lxml.objectify import fromstring as parse_xml
	
	body = await req.read()
	root = parse_xml(body)
	
	token_tag = root.find('.//{*}PassportCookie/{*}*[1]')
	if get_tag_localname(token_tag) is not 't':
		token = None
	token = token_tag.text
	if token is not None:
		token = token[0:20]
	
	backend: Backend = req.app['backend']
	bs = backend.util_get_sess_by_token(token)
	
	header = find_element(root, 'Header')
	action = find_element(root, 'Body/*[1]')
	if settings.DEBUG and settings.DEBUG_MSNP: print('Action: {}'.format(get_tag_localname(action)))
	
	return header, action, bs, token

async def preprocess_soap_oimws(req: web.Request) -> Tuple[Any, str, str, Optional[BackendSession], str]:
	from lxml.objectify import fromstring as parse_xml
	
	body = await req.read()
	root = parse_xml(body)
	
	token = root.find('.//{*}Ticket').get('passport')
	if token[0:2] == 't=':
		token = token[2:22]
	
	backend: Backend = req.app['backend']
	bs = backend.util_get_sess_by_token(token)
	
	header = find_element(root, 'Header')
	body_msgtype = str(find_element(root, 'Body/MessageType'))
	body_content = str(find_element(root, 'Body/Content')).replace('\r\n', '\n')
	
	return header, body_msgtype, body_content, bs, token

async def handle_textad(req: web.Request) -> web.Response:
	with open(ETC_DIR + '/textads.json') as f:
		textads = json.loads(f.read())
		f.close()
	
	if len(textads) == 0: return web.HTTPOk()
	
	if len(textads) > 1:
		ad = textads[secrets.randbelow((len(textads)-1))]
	else:
		ad = textads[0]
	return render(req, 'msn:textad.xml', {
		'caption': ad['caption'],
		'hiturl': ad['hiturl'],
	})

async def handle_msgrconfig(req: web.Request) -> web.Response:
	if req.method == 'POST':
		body = await req.read() # type: Optional[bytes]
	else:
		body = None
	msgr_config = _get_msgr_config(req, body)
	if msgr_config == 'INVALID_VER':
		return web.Response(status = 500)
	return web.HTTPOk(content_type = 'text/xml', text = msgr_config)

def _get_msgr_config(req: web.Request, body: Optional[bytes]) -> str:
	query = req.query
	result = None # type: Optional[str]
	
	if query.get('ver') is not None:
		if re.match(r'[^\d\.]', query.get('ver')):
			return 'INVALID_VER'
		
		config_ver = query.get('ver').split('.', 4)
		if 5 <= int(config_ver[0]) <= 7:
			with open(TMPL_DIR + '/MsgrConfig.msn.envelope.xml') as fh:
				envelope = fh.read()
			with open(TMPL_DIR + '/MsgrConfig.msn.xml') as fh:
				config = fh.read()
			with open(TMPL_DIR + '/MsgrConfig.tabs.xml') as fh:
				config_tabs = fh.read()
			result = envelope.format(MsgrConfig = config.format(tabs = config_tabs))
		elif 8 <= int(config_ver[0]) <= 9:
			with open(TMPL_DIR + '/MsgrConfig.wlm.8.xml') as fh:
				config = fh.read()
			with open(TMPL_DIR + '/MsgrConfig.tabs.xml') as fh:
				config_tabs = fh.read()
			result = config.format(tabs = config_tabs)
		elif int(config_ver[0]) >= 14:
			with open(TMPL_DIR + '/MsgrConfig.wlm.14.xml') as fh:
				config = fh.read()
			# TODO: Tabs in WLM 2009+
			#with open(TMPL_DIR + '/MsgrConfig.tabs.xml') as fh:
			#	config_tabs = fh.read()
			result = config.format()
	elif body is not None:
		with open(TMPL_DIR + '/MsgrConfig.msn.envelope.xml') as fh:
			envelope = fh.read()
		with open(TMPL_DIR + '/MsgrConfig.msn.xml') as fh:
			config = fh.read()
		with open(TMPL_DIR + '/MsgrConfig.tabs.xml') as fh:
			config_tabs = fh.read()
		result = envelope.format(MsgrConfig = config.format(tabs = config_tabs))
	
	return result or ''

PassportURLs = 'PassportURLs'
if settings.DEBUG:
	# Caddy (on the live server) standardizes all header names, and so
	# turns this into 'Passporturls'. Because of this, patching MSN
	# involves changing that string in the executable as well.
	# But then if you try to use a patched MSN with a dev server, it
	# won't work, so we have to standardize the header name here.
	PassportURLs = PassportURLs.title()

async def handle_nexus(req: web.Request) -> web.Response:
	return web.HTTPOk(headers = {
		PassportURLs: 'DALogin=https://{}{}'.format(settings.LOGIN_HOST, LOGIN_PATH),
	})

async def handle_login(req: web.Request) -> web.Response:
	tmp = _extract_pp_credentials(req.headers.get('Authorization'))
	if tmp is None:
		token = None
	else:
		email, pwd = tmp
		token = _login(req, email, pwd)
	if token is None:
		raise web.HTTPUnauthorized(headers = {
			'WWW-Authenticate': '{}da-status=failed'.format(PP),
		})
	return web.HTTPOk(headers = {
		'Authentication-Info': '{}da-status=success,from-PP=\'{}\''.format(PP, token),
	})

async def handle_not_rst(req: web.Request) -> web.Response:
	if req.method == 'OPTIONS':
		return web.HTTPOk(headers = {
			'Access-Control-Allow-Origin': '*',
			'Access-Control-Allow-Methods': 'POST',
			'Access-Control-Allow-Headers': 'X-User, X-Password, Content-Type',
			'Access-Control-Expose-Headers': 'X-Token',
			'Access-Control-Max-Age': str(86400),
		})
	
	email = req.headers.get('X-User')
	pwd = req.headers.get('X-Password')
	token = _login(req, email, pwd, lifetime = 86400)
	headers = {
		'Access-Control-Allow-Origin': '*',
		'Access-Control-Allow-Methods': 'POST',
		'Access-Control-Expose-Headers': 'X-Token',
	}
	if token is not None:
		headers['X-Token'] = token
	return web.HTTPOk(headers = headers)

async def handle_rst(req: web.Request, rst2: bool = False) -> web.Response:
	from lxml.objectify import fromstring as parse_xml
	
	body = await req.read()
	root = parse_xml(body)
	
	email = find_element(root, 'Username')
	pwd = str(find_element(root, 'Password'))

	if email is None or pwd is None:
		raise web.HTTPBadRequest()
	
	backend: Backend = req.app['backend']
	
	token = _login(req, email, pwd, binary_secret = True, lifetime = 86400)
	
	uuid = backend.util_get_uuid_from_email(email)
	
	if token is not None and uuid is not None:
		day_before_expiry = datetime.utcfromtimestamp((backend.auth_service.get_token_expiry('nb/login', token) or 0) - 86400)
		timez = util.misc.date_format(day_before_expiry)
		tomorrowz = util.misc.date_format((day_before_expiry + timedelta(days = 1)))
		time_5mz = util.misc.date_format((day_before_expiry + timedelta(minutes = 5)))
		
		# load PUID and CID, assume them to be the same for our purposes
		cid = cid_format(uuid)
		
		assert req.transport is not None
		peername = req.transport.get_extra_info('peername')
		if peername:
			host = peername[0]
		else:
			host = '127.0.0.1'
		
		# get list of requested domains
		domains = root.findall('.//{*}Address')
		domains.remove('http://Passport.NET/tb') # ignore Passport token request
		
		tpl = backend.auth_service.get_token('nb/login', token) # type: Optional[Tuple[str, Optional[str]]]
		assert tpl is not None
		_, bsecret = tpl
		
		tmpl = req.app['jinja_env'].get_template(('msn:RST/RST2.token.xml' if rst2 else 'msn:RST/RST.token.xml'))
		# collect tokens for requested domains
		tokenxmls = [tmpl.render(
			i = i + 1,
			domain = domain,
			timez = timez,
			tomorrowz = tomorrowz,
			pptoken1 = token,
			binarysecret = bsecret,
		) for i, domain in enumerate(domains)]
		
		tmpl = req.app['jinja_env'].get_template(('msn:RST/RST2.xml' if rst2 else 'msn:RST/RST.xml'))
		return web.HTTPOk(
			content_type = 'text/xml',
			text = (tmpl.render(
				puidhex = cid.upper(),
				time_5mz = time_5mz,
				timez = timez,
				tomorrowz = tomorrowz,
				cid = cid,
				email = email,
				firstname = "John",
				lastname = "Doe",
				ip = host,
				pptoken1 = token,
				tokenxml = Markup(''.join(tokenxmls)),
			) if rst2 else tmpl.render(
				puidhex = cid.upper(),
				timez = timez,
				tomorrowz = tomorrowz,
				cid = cid,
				email = email,
				firstname = "John",
				lastname = "Doe",
				ip = host,
				pptoken1 = token,
				tokenxml = Markup(''.join(tokenxmls)),
			)),
		)
	
	return render(req, 'msn:RST/RST.error.xml', {
		'timez': util.misc.date_format(datetime.utcnow()),
	}, status = 403)

def _get_storage_path(uuid: str) -> Path:
	return Path('storage/dp') / uuid[0:1] / uuid[0:2]

def handle_create_document(req: web.Request, action: Any, user: models.User, cid: str, token: str, timestamp: int) -> web.Response:
	from PIL import Image
	
	# get image data
	name = find_element(action, 'Name')
	streamtype = find_element(action, 'DocumentStreamType')
	
	if streamtype == 'UserTileStatic':
		mime = find_element(action, 'MimeType')
		data = find_element(action, 'Data')
		data = base64.b64decode(data)
		
		# store display picture as file
		path = _get_storage_path(user.uuid)
		path.mkdir(exist_ok = True)
		
		image_path = path / '{uuid}.{mime}'.format(uuid = user.uuid, mime = mime)
		
		image_path.write_bytes(data)
		
		image = Image.open(image_path)
		thumb = image.resize((21, 21))
		
		thumb_path = path / '{uuid}_thumb.{mime}'.format(uuid = user.uuid, mime = mime)
		thumb.save(str(thumb_path))
	
	return render(req, 'msn:storageservice/CreateDocumentResponse.xml', {
		'user': user,
		'cid': cid,
		'pptoken1': token,
		'timestamp': timestamp,
	})

async def handle_usertile(req: web.Request, small: bool = False) -> web.Response:
	uuid = req.match_info['uuid']
	storage_path = _get_storage_path(uuid)
	files = list(storage_path.iterdir())
	
	if not files:
		raise web.HTTPNotFound()
	
	ext = files[0].suffix
	image_path = storage_path / '{}{}.{}'.format(uuid, '_thumb' if small else '', ext)
	return web.HTTPOk(content_type = 'image/{}'.format(ext), body = image_path.read_bytes())

async def handle_debug(req: web.Request) -> web.Response:
	return render(req, 'msn:debug.html')

def _extract_pp_credentials(auth_str: str) -> Optional[Tuple[str, str]]:
	if auth_str is None:
		return None
	assert auth_str.startswith(PP)
	auth = {}
	for part in auth_str[len(PP):].split(','):
		parts = part.split('=', 1)
		if len(parts) == 2:
			auth[unquote(parts[0])] = unquote(parts[1])
	email = auth['sign-in']
	pwd = auth['pwd']
	return email, pwd

def _login(req: web.Request, email: str, pwd: str, binary_secret: bool = False, lifetime: int = 30) -> Optional[str]:
	backend: Backend = req.app['backend']
	bsecret = None
	uuid = backend.user_service.login(email, pwd)
	if uuid is None: return None
	return backend.auth_service.create_token('nb/login', (uuid, base64.b64encode(secrets.token_bytes(24)).decode('ascii') if binary_secret else None), lifetime = lifetime)

def _contact_is_favorite(groups: Dict[str, models.Group], ctc: models.AddressBookContact) -> bool:
	for group_id in ctc.groups:
		if group_id not in groups: continue
		if groups[group_id].is_favorite: return True
	return False
