-- Office Tech Health Check: durable rate limiting and audit log for the technician tools.
--
-- Only the serverless functions use these, with the service-role key (SUPABASE_SERVICE_ROLE_KEY).
-- Row level security is on and there are deliberately NO policies for anon or authenticated, so the
-- public API keys can't read or write anything here. The service role bypasses RLS.

-- ---------------------------------------------------------------------------
-- Rate limiting: one row per key (e.g. "login-ip:203.0.113.5"), fixed windows.
-- ---------------------------------------------------------------------------
create table if not exists public.rate_limit (
  key          text primary key,
  hits         integer     not null default 0,
  window_start timestamptz not null default now(),
  expires_at   timestamptz not null
);

create index if not exists rate_limit_expires_at_idx on public.rate_limit (expires_at);

alter table public.rate_limit enable row level security;
revoke all on table public.rate_limit from anon, authenticated;

-- Atomically add p_increment hits to p_key's current window (a new window starts when the old one
-- has expired) and return the total and when the window resets. p_increment = 0 just reads it.
-- A single INSERT ... ON CONFLICT statement, so concurrent requests can't lose updates.
create or replace function public.rate_limit_hit(p_key text, p_window_seconds integer, p_increment integer default 1)
returns table (hits integer, reset_at timestamptz)
language plpgsql
security definer
set search_path = public
as $$
#variable_conflict use_column
begin
  if p_key is null or length(p_key) > 200 or p_window_seconds is null or p_window_seconds < 1 or p_window_seconds > 86400
     or p_increment is null or p_increment < 0 or p_increment > 100 then
    raise exception 'invalid rate limit arguments';
  end if;

  return query
  insert into public.rate_limit as r (key, hits, window_start, expires_at)
  values (p_key, p_increment, now(), now() + make_interval(secs => p_window_seconds))
  on conflict (key) do update set
    hits         = case when r.expires_at <= now() then excluded.hits else r.hits + excluded.hits end,
    window_start = case when r.expires_at <= now() then now() else r.window_start end,
    expires_at   = case when r.expires_at <= now() then excluded.expires_at else r.expires_at end
  returning r.hits, r.expires_at;

  -- Keep the table small: occasionally drop windows that ended more than a day ago.
  if random() < 0.02 then
    delete from public.rate_limit where expires_at < now() - interval '1 day';
  end if;
end;
$$;

revoke all on function public.rate_limit_hit(text, integer, integer) from public, anon, authenticated;
grant execute on function public.rate_limit_hit(text, integer, integer) to service_role;

-- ---------------------------------------------------------------------------
-- Audit log: login, logout, plan builds/confirmations and live verifications.
-- Never contains access codes or uploaded zone contents (only their SHA-256 and size).
-- ---------------------------------------------------------------------------
create table if not exists public.audit_log (
  id         bigint generated always as identity primary key,
  ts         timestamptz not null default now(),
  event      text        not null,
  sid        text,
  ip         text,
  user_agent text,
  domain     text,
  data       jsonb       not null default '{}'::jsonb
);

create index if not exists audit_log_ts_idx on public.audit_log (ts desc);
create index if not exists audit_log_event_ts_idx on public.audit_log (event, ts desc);
create index if not exists audit_log_domain_ts_idx on public.audit_log (domain, ts desc);

alter table public.audit_log enable row level security;
revoke all on table public.audit_log from anon, authenticated;

-- Append one event and keep only the newest 5000 rows.
create or replace function public.audit_append(p_event jsonb)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  cutoff bigint;
begin
  if p_event is null or coalesce(p_event->>'event', '') = '' then
    raise exception 'audit event name is required';
  end if;

  insert into public.audit_log (ts, event, sid, ip, user_agent, domain, data)
  values (
    coalesce((p_event->>'ts')::timestamptz, now()),
    left(p_event->>'event', 64),
    left(p_event->>'sid', 64),
    left(p_event->>'ip', 64),
    left(p_event->>'ua', 512),
    left(p_event->>'domain', 253),
    p_event
  );

  select id into cutoff from public.audit_log order by id desc offset 5000 limit 1;
  if cutoff is not null then
    delete from public.audit_log where id <= cutoff;
  end if;
end;
$$;

revoke all on function public.audit_append(jsonb) from public, anon, authenticated;
grant execute on function public.audit_append(jsonb) to service_role;
