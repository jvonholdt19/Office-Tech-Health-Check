-- DMARC Tracker: staged rollout monitoring for client domains.
-- Feature 2: Track client domains through three DMARC stages (none → quarantine → reject).

-- ---------------------------------------------------------------------------
-- DMARC tracking: per-domain tracking state, stage progression, and history.
-- ---------------------------------------------------------------------------
create table if not exists public.dmarc_tracker (
  id               bigint generated always as identity primary key,
  domain           text        not null unique,
  stage            integer     not null default 1 check (stage in (1, 2, 3)),
  stage_started_at timestamptz not null default now(),
  last_check_at    timestamptz,
  last_check_result jsonb,
  can_advance      boolean     not null default false,
  advance_note     text,
  created_at       timestamptz not null default now(),
  updated_at       timestamptz not null default now(),
  created_by       text,
  notes            text
);

create index if not exists dmarc_tracker_domain_idx on public.dmarc_tracker (domain);
create index if not exists dmarc_tracker_stage_idx on public.dmarc_tracker (stage, can_advance);
create index if not exists dmarc_tracker_updated_idx on public.dmarc_tracker (updated_at desc);

alter table public.dmarc_tracker enable row level security;
revoke all on table public.dmarc_tracker from anon, authenticated;

-- History: stage transitions and manual notes.
create table if not exists public.dmarc_tracker_history (
  id         bigint generated always as identity primary key,
  tracker_id bigint      not null references public.dmarc_tracker(id) on delete cascade,
  ts         timestamptz not null default now(),
  event      text        not null,
  data       jsonb       not null default '{}'::jsonb
);

create index if not exists dmarc_tracker_history_tracker_idx on public.dmarc_tracker_history (tracker_id, ts desc);
create index if not exists dmarc_tracker_history_ts_idx on public.dmarc_tracker_history (ts desc);

alter table public.dmarc_tracker_history enable row level security;
revoke all on table public.dmarc_tracker_history from anon, authenticated;

-- Add a tracked domain or return existing.
create or replace function public.dmarc_tracker_add(
  p_domain text,
  p_created_by text default null,
  p_notes text default null
)
returns bigint
language plpgsql
security definer
set search_path = public
as $$
declare
  v_id bigint;
begin
  if p_domain is null or length(p_domain) = 0 or length(p_domain) > 253 then
    raise exception 'invalid domain';
  end if;

  insert into public.dmarc_tracker (domain, stage, created_by, notes)
  values (lower(p_domain), 1, p_created_by, p_notes)
  on conflict (domain) do update set
    updated_at = now(),
    notes = coalesce(excluded.notes, dmarc_tracker.notes)
  returning id into v_id;

  insert into public.dmarc_tracker_history (tracker_id, event, data)
  values (v_id, 'added', jsonb_build_object('created_by', p_created_by, 'notes', p_notes));

  return v_id;
end;
$$;

revoke all on function public.dmarc_tracker_add(text, text, text) from public, anon, authenticated;
grant execute on function public.dmarc_tracker_add(text, text, text) to service_role;

-- Update check result and advance eligibility.
create or replace function public.dmarc_tracker_update_check(
  p_id bigint,
  p_result jsonb,
  p_can_advance boolean,
  p_advance_note text default null
)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  update public.dmarc_tracker
  set
    last_check_at = now(),
    last_check_result = p_result,
    can_advance = p_can_advance,
    advance_note = p_advance_note,
    updated_at = now()
  where id = p_id;

  insert into public.dmarc_tracker_history (tracker_id, event, data)
  values (p_id, 'check', jsonb_build_object(
    'can_advance', p_can_advance,
    'note', p_advance_note,
    'result', p_result
  ));
end;
$$;

revoke all on function public.dmarc_tracker_update_check(bigint, jsonb, boolean, text) from public, anon, authenticated;
grant execute on function public.dmarc_tracker_update_check(bigint, jsonb, boolean, text) to service_role;

-- Advance a domain to the next stage.
create or replace function public.dmarc_tracker_advance(
  p_id bigint,
  p_skip_to_stage integer default null,
  p_confirmed_by text default null,
  p_note text default null
)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  v_current_stage integer;
  v_new_stage integer;
begin
  select stage into v_current_stage from public.dmarc_tracker where id = p_id;
  if v_current_stage is null then
    raise exception 'tracker not found';
  end if;

  if p_skip_to_stage is not null then
    if p_skip_to_stage not in (1, 2, 3) or p_skip_to_stage <= v_current_stage then
      raise exception 'invalid skip target stage';
    end if;
    v_new_stage := p_skip_to_stage;
  else
    v_new_stage := least(v_current_stage + 1, 3);
  end if;

  update public.dmarc_tracker
  set
    stage = v_new_stage,
    stage_started_at = now(),
    can_advance = false,
    advance_note = null,
    updated_at = now()
  where id = p_id;

  insert into public.dmarc_tracker_history (tracker_id, event, data)
  values (p_id, 'advanced', jsonb_build_object(
    'from_stage', v_current_stage,
    'to_stage', v_new_stage,
    'skipped', p_skip_to_stage is not null,
    'confirmed_by', p_confirmed_by,
    'note', p_note
  ));
end;
$$;

revoke all on function public.dmarc_tracker_advance(bigint, integer, text, text) from public, anon, authenticated;
grant execute on function public.dmarc_tracker_advance(bigint, integer, text, text) to service_role;

-- Remove a domain from tracking.
create or replace function public.dmarc_tracker_remove(p_id bigint)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  delete from public.dmarc_tracker where id = p_id;
end;
$$;

revoke all on function public.dmarc_tracker_remove(bigint) from public, anon, authenticated;
grant execute on function public.dmarc_tracker_remove(bigint) to service_role;
