def load_dashboard(cur, tenant_table):
~>    query = f"""select u.id, u.email, t.name, s.plan, i.total, l.last_seen
        from users u
        inner join teams t on t.id = u.team_id
        left outer join subscriptions s on s.team_id = t.id
        left join invoices i on i.subscription_id = s.id
        join {tenant_table} x on x.user_id = u.id
        left join logins l on l.user_id = u.id
        where u.active = true
    """
    cur.execute(query)
    return cur.fetchall()
