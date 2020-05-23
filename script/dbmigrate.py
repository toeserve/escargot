from itertools import groupby
import db

def main():
	User = db.User
	t_user = User.__table__
	
	with db.Session() as sess:
		print("reading data")
		data = sess.query(User.id, User.uuid, User.email, User.groups, User.contacts).all()
		
		data = sorted(data, key = lambda row: (row.email.lower(), row.id))
		row_uuids = set()
		contact_uuids = set()
		for row in data:
			row_uuids.add(row.uuid)
			contact_uuids |= { c['uuid'] for c in row.contacts }
		print("uuids", len(row_uuids))
		print("extra contact_uuids", len(contact_uuids - row_uuids))
		
		uuid_to_canon = {}
		for _, rows in groupby(data, key = lambda row: row.email.lower()):
			rows = list(rows)
			if len(rows) < 2:
				continue
			main_row, *rows = sorted(rows, key = lambda row: (-row_activity(row), row.id))
			for row in rows:
				row_uuids.discard(row.uuid)
				uuid_to_canon[row.uuid] = main_row.uuid
		
		canon_contacts = merge_contacts(data, uuid_to_canon, row_uuids)
		print("update contacts", len(canon_contacts))
		for uuid, contacts in canon_contacts.items():
			sess.execute(t_user.update().where(t_user.c.uuid == uuid).values(contacts = contacts))
		
		delete_ids = { row.id for row in data if row.uuid in uuid_to_canon }
		print("delete", len(delete_ids))
		sess.execute(t_user.delete().where(t_user.c.id.in_(delete_ids)))
		
		sess.execute('CREATE UNIQUE INDEX email_ci_index ON t_user (LOWER(email))')
		sess.execute('DROP TABLE t_sound')

def merge_contacts(data, uuid_to_canon, row_uuids):
	data_by_uuid = {
		row.uuid: row for row in data
	}
	changed_contacts = {}
	
	for row in data:
		uuid_canon = uuid_to_canon.get(row.uuid)
		if uuid_canon is None:
			if row.uuid not in changed_contacts:
				changed_contacts[row.uuid] = []
			merge_contacts_for_user(row, changed_contacts[row.uuid], row_uuids)
		else:
			row_canon = data_by_uuid[uuid_canon]
			if uuid_canon not in changed_contacts:
				changed_contacts[uuid_canon] = []
			merge_contacts_for_user(row, changed_contacts[uuid_canon], row_uuids)
	
	return {
		uuid: contacts
		for uuid, contacts in changed_contacts.items()
		if {c['uuid'] for c in contacts} != { c['uuid'] for c in data_by_uuid[uuid].contacts }
	}

def merge_contacts_for_user(row, contacts, row_uuids):
	contact_uuids = { c['uuid'] for c in contacts }
	
	for c in row.contacts:
		if c['uuid'] not in row_uuids:
			continue
		if c['uuid'] in contact_uuids:
			continue
		# Too complicated to merge groups
		c['groups'] = []
		contacts.append(c)

def row_activity(row):
	return len(row.groups) + len(row.contacts)

if __name__ == '__main__':
	main()
