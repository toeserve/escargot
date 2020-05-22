import db

with db.Session() as sess:
	sess.execute('DELETE FROM t_user WHERE t_user.email NOT IN (SELECT email FROM t_user GROUP BY LOWER(email))')
	sess.execute('CREATE UNIQUE INDEX email_ci_index ON t_user (LOWER(email))')
	sess.execute('DROP TABLE t_sound')
