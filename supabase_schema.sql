-- Безпечна схема Між нами. Запусти весь SQL у Supabase → SQL Editor → Run.
-- Використовує окремі таблиці mn_*; наявні таблиці не видаляються.
create extension if not exists pgcrypto;
create table if not exists public.mn_profiles(id uuid primary key references auth.users(id) on delete cascade,username text not null unique check(username ~ '^[a-z0-9_]{3,24}$'),display_name text not null check(char_length(display_name) between 1 and 32),bio text not null default '' check(char_length(bio)<=160),avatar_url text,created_at timestamptz not null default now());
create table if not exists public.mn_friend_requests(id uuid primary key default gen_random_uuid(),sender_id uuid not null references auth.users(id) on delete cascade,receiver_id uuid not null references auth.users(id) on delete cascade,status text not null default 'pending' check(status in('pending','accepted','declined')),created_at timestamptz not null default now(),check(sender_id<>receiver_id),unique(sender_id,receiver_id));
create table if not exists public.mn_friendships(user_low uuid not null references auth.users(id) on delete cascade,user_high uuid not null references auth.users(id) on delete cascade,created_at timestamptz not null default now(),primary key(user_low,user_high),check(user_low<user_high));
create table if not exists public.mn_spaces(id uuid primary key default gen_random_uuid(),invite_code text not null unique,name text not null default 'Наш простір',created_by uuid not null references auth.users(id) on delete cascade,created_at timestamptz not null default now());
create table if not exists public.mn_space_members(space_id uuid not null references public.mn_spaces(id) on delete cascade,user_id uuid not null references auth.users(id) on delete cascade,joined_at timestamptz not null default now(),primary key(space_id,user_id));
create table if not exists public.mn_space_notes(id uuid primary key default gen_random_uuid(),space_id uuid not null references public.mn_spaces(id) on delete cascade,user_id uuid not null references auth.users(id) on delete cascade,body text not null check(char_length(body) between 1 and 1000),created_at timestamptz not null default now());

-- Допоміжна функція перевіряє членство без рекурсії RLS.
create or replace function public.mn_is_member(target_space uuid)
returns boolean language sql stable security definer set search_path=public
as $$ select exists(select 1 from public.mn_space_members where space_id=target_space and user_id=auth.uid()) $$;

-- Безпечне приєднання за кодом: код не відкриває список усіх просторів.
create or replace function public.mn_join_space(code text)
returns table(id uuid, invite_code text, name text, created_by uuid)
language plpgsql security definer set search_path=public
as $$
declare s public.mn_spaces%rowtype;
begin
  if auth.uid() is null then raise exception 'Потрібен вхід'; end if;
  select * into s from public.mn_spaces where invite_code=upper(trim(code));
  if not found then raise exception 'Простір не знайдено'; end if;
  insert into public.mn_space_members(space_id,user_id) values(s.id,auth.uid())
  on conflict(space_id,user_id) do nothing;
  return query select s.id,s.invite_code,s.name,s.created_by;
end $$;
grant execute on function public.mn_join_space(text) to authenticated;

alter table public.mn_profiles enable row level security;alter table public.mn_friend_requests enable row level security;alter table public.mn_friendships enable row level security;alter table public.mn_spaces enable row level security;alter table public.mn_space_members enable row level security;alter table public.mn_space_notes enable row level security;
drop policy if exists mn_profiles_read on public.mn_profiles;create policy mn_profiles_read on public.mn_profiles for select to authenticated using(true);
drop policy if exists mn_profiles_insert on public.mn_profiles;create policy mn_profiles_insert on public.mn_profiles for insert to authenticated with check(id=auth.uid());
drop policy if exists mn_profiles_update on public.mn_profiles;create policy mn_profiles_update on public.mn_profiles for update to authenticated using(id=auth.uid()) with check(id=auth.uid());
create or replace function public.mn_new_user() returns trigger language plpgsql security definer set search_path=public as $$ declare u text; n text; begin u:=lower(coalesce(new.raw_user_meta_data->>'username','user_'||substr(new.id::text,1,8)));u:=regexp_replace(u,'[^a-z0-9_]','','g');if char_length(u)<3 then u:='user_'||substr(new.id::text,1,8);end if;u:=substr(u,1,24);n:=left(coalesce(nullif(trim(new.raw_user_meta_data->>'display_name'),''),u),32);insert into public.mn_profiles(id,username,display_name) values(new.id,u,n) on conflict(id) do nothing;return new;end $$;
drop trigger if exists mn_auth_user_created on auth.users;create trigger mn_auth_user_created after insert on auth.users for each row execute procedure public.mn_new_user();
drop policy if exists mn_req_read on public.mn_friend_requests;create policy mn_req_read on public.mn_friend_requests for select to authenticated using(sender_id=auth.uid() or receiver_id=auth.uid());
drop policy if exists mn_req_insert on public.mn_friend_requests;create policy mn_req_insert on public.mn_friend_requests for insert to authenticated with check(sender_id=auth.uid() and sender_id<>receiver_id);
drop policy if exists mn_req_update on public.mn_friend_requests;create policy mn_req_update on public.mn_friend_requests for update to authenticated using(receiver_id=auth.uid() and status='pending') with check(receiver_id=auth.uid() and status in('accepted','declined'));
drop policy if exists mn_friend_read on public.mn_friendships;create policy mn_friend_read on public.mn_friendships for select to authenticated using(user_low=auth.uid() or user_high=auth.uid());
drop policy if exists mn_friend_insert on public.mn_friendships;create policy mn_friend_insert on public.mn_friendships for insert to authenticated with check((user_low=auth.uid() or user_high=auth.uid()) and exists(select 1 from public.mn_friend_requests r where r.status='pending' and r.receiver_id=auth.uid() and ((r.sender_id=user_low and r.receiver_id=user_high) or (r.sender_id=user_high and r.receiver_id=user_low))));
drop policy if exists mn_friend_delete on public.mn_friendships;create policy mn_friend_delete on public.mn_friendships for delete to authenticated using(user_low=auth.uid() or user_high=auth.uid());
drop policy if exists mn_spaces_read on public.mn_spaces;create policy mn_spaces_read on public.mn_spaces for select to authenticated using(public.mn_is_member(id));
drop policy if exists mn_spaces_insert on public.mn_spaces;create policy mn_spaces_insert on public.mn_spaces for insert to authenticated with check(created_by=auth.uid());
drop policy if exists mn_members_read on public.mn_space_members;create policy mn_members_read on public.mn_space_members for select to authenticated using(user_id=auth.uid());
drop policy if exists mn_members_insert on public.mn_space_members;create policy mn_members_insert on public.mn_space_members for insert to authenticated with check(user_id=auth.uid() and (public.mn_is_member(space_id) or exists(select 1 from public.mn_spaces s where s.id=space_id and s.created_by=auth.uid())));
drop policy if exists mn_notes_read on public.mn_space_notes;create policy mn_notes_read on public.mn_space_notes for select to authenticated using(public.mn_is_member(space_id));
drop policy if exists mn_notes_insert on public.mn_space_notes;create policy mn_notes_insert on public.mn_space_notes for insert to authenticated with check(user_id=auth.uid() and (public.mn_is_member(space_id) or exists(select 1 from public.mn_spaces s where s.id=space_id and s.created_by=auth.uid())));
grant usage on schema public to authenticated;grant select,insert,update on public.mn_profiles to authenticated;grant select,insert,update on public.mn_friend_requests to authenticated;grant select,insert,delete on public.mn_friendships to authenticated;grant select,insert on public.mn_spaces,public.mn_space_members,public.mn_space_notes to authenticated;