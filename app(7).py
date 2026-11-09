# 수정 버전: 이메일 대신 아이디 로그인. Supabase 사용 시 Authentication → Providers → Email → Confirm email을 끄세요.
# 아이디는 내부적으로 @study.invalid 주소로 매핑되며 실제 이메일은 수집하지 않습니다.
# 기존 이메일 계정은 자동 이전되지 않습니다. Cloud 로컬 저장은 임시 저장입니다.
"""끝까지 — Streamlit 학습 플래너
실행: streamlit run app.py
설정: Streamlit 앱 Settings → Secrets에 아래 입력 (GitHub에 올리지 마세요).
SUPABASE_URL = "https://프로젝트.supabase.co"
SUPABASE_ANON_KEY = "프로젝트의 anon 또는 publishable key"

Supabase SQL Editor에서 아래 SQL을 한 번 실행하세요.
create table public.study_plans (
 user_id uuid primary key references auth.users(id) on delete cascade,
 payload jsonb not null default '{"goals":[]}'::jsonb,
 version integer not null default 0
);
alter table public.study_plans enable row level security;
create policy "read own" on public.study_plans for select to authenticated
 using ((select auth.uid()) = user_id);
create policy "insert own" on public.study_plans for insert to authenticated
 with check ((select auth.uid()) = user_id);
create policy "update own" on public.study_plans for update to authenticated
 using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);
grant select, insert, update on public.study_plans to authenticated;

Authentication → Providers에서 Email 로그인을 활성화하고 Confirm email을 끄세요.
실제 이메일 대신 아이디를 내부 주소로 변환해 사용합니다.
비밀번호 재설정 메일은 Supabase 기본 인증 화면을 별도로 구성해야 합니다.
이 앱은 비밀번호 재설정 UI를 제공하지 않습니다.
service_role/secret key는 절대 사용하지 마세요. RLS를 해제하지 마세요.
공개 배포 후 주소로 QR을 만들면 됩니다. QR에 계정/키를 넣지 마세요.
"""
from datetime import date, datetime, timedelta
from zoneinfo import ZoneInfo
import html
import copy
import uuid
import requests
import sqlite3
import hashlib
import secrets
import json
import streamlit as st
import streamlit.config as _streamlit_config

# 이 앱은 밝은 테마만 사용합니다. 배포 환경의 기본 다크 테마도 덮어씁니다.
for _key, _value in {
    "theme.base": "light",
    "theme.primaryColor": "#4263EB",
    "theme.backgroundColor": "#F6F8FC",
    "theme.secondaryBackgroundColor": "#FFFFFF",
    "theme.textColor": "#202D45",
}.items():
    _streamlit_config.set_option(_key, _value)


WEEKDAYS = ['월', '화', '수', '목', '금', '토', '일']


def study_days(start, end, weekdays):
    if end < start:
        return []
    return [start + timedelta(days=i) for i in range((end-start).days+1)
            if (start + timedelta(days=i)).weekday() in weekdays]


def allocate(total, days):
    """정수 분배: 합은 total, 날마다 차이는 최대 1."""
    if not days:
        return {}
    q, r = divmod(total, len(days))
    return {d.isoformat(): q + (i < r) for i, d in enumerate(days)}


def plan(goal, today):
    """오늘 이전 진도를 제외한 분량을 오늘부터 배분: 오늘 기록 중 목표는 고정."""
    logs = goal['logs']
    before = sum(int(v) for k, v in logs.items() if k < today.isoformat())
    days = study_days(max(date.fromisoformat(goal['start']), today),
                      date.fromisoformat(goal['end']), goal['weekdays'])
    baseline = allocate(max(0, goal['total'] - before), days)
    target = baseline.get(today.isoformat(), 0)
    done_today = int(logs.get(today.isoformat(), 0))
    remaining = max(0, goal['total'] - sum(int(v) for v in logs.values()))
    future_days = [d for d in days if d > today]
    # 오늘 잔여 목표를 먼저 확보하고 내일부터 실제 진도에 맞춰 배분.
    today_left = min(remaining, max(0, target - done_today))
    future = allocate(remaining - today_left, future_days)
    return target, remaining, days, future


def local_api(method, path, token=None, body=None, prefer=None):
    """설정 없는 체험용 저장. Cloud의 로컬 파일은 영구 보관을 보장하지 않음."""
    with sqlite3.connect('study_local.sqlite3', timeout=20) as db:
        db.execute('create table if not exists users (id text primary key, email text unique, salt text, digest text)')
        db.execute('create table if not exists sessions (token text primary key, uid text)')
        db.execute('create table if not exists plans (uid text primary key, payload text, version integer)')
        if path.startswith('/auth/v1/signup') or path.startswith('/auth/v1/token?grant_type=password'):
            email = body['email'].strip().lower()
            password = body['password']
            if path.startswith('/auth/v1/signup'):
                salt = secrets.token_hex(16)
                digest = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), 260000).hex()
                uid = uuid.uuid4().hex
                try:
                    db.execute('insert into users values (?,?,?,?)', (uid,email,salt,digest))
                except sqlite3.IntegrityError:
                    raise RuntimeError('이미 가입된 아이디예요. 로그인을 선택해 주세요.')
            else:
                row = db.execute('select id,salt,digest from users where email=?', (email,)).fetchone()
                if not row:
                    raise RuntimeError('아이디 또는 비밀번호를 확인해 주세요. 처음이라면 회원가입을 선택하세요.')
                uid,salt,expected = row
                actual = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), 260000).hex()
                if not secrets.compare_digest(actual, expected):
                    raise RuntimeError('아이디 또는 비밀번호를 확인해 주세요. 처음이라면 회원가입을 선택하세요.')
            access = secrets.token_urlsafe(32)
            db.execute('insert into sessions values (?,?)', (access,uid))
            return {'access_token':access, 'user':{'id':uid}}
        row = db.execute('select uid from sessions where token=?', (token,)).fetchone()
        if not row:
            raise RuntimeError('로그인이 만료되었어요. 로그아웃 후 다시 로그인해 주세요.')
        uid = row[0]
        if path.startswith('/auth/v1/logout'):
            db.execute('delete from sessions where token=?', (token,))
            return None
        if not path.startswith('/rest/v1/study_plans'):
            raise RuntimeError('지원하지 않는 요청이에요.')
        if method == 'GET':
            row = db.execute('select payload,version from plans where uid=?', (uid,)).fetchone()
            return [{'payload':json.loads(row[0]), 'version':row[1]}] if row else []
        if method == 'POST':
            db.execute('insert or ignore into plans values (?,?,?)', (uid,json.dumps(body['payload']),body['version']))
            return None
        if method == 'PATCH':
            version = int(path.rsplit('version=eq.',1)[1])
            result = db.execute('update plans set payload=?,version=? where uid=? and version=?',
                                (json.dumps(body['payload']),body['version'],uid,version))
            return [body] if result.rowcount else []
        raise RuntimeError('지원하지 않는 요청이에요.')


def api(method, path, token=None, body=None, prefer=None):
    if not st.session_state.get('cloud_storage', False):
        return local_api(method, path, token, body, prefer)
    headers = {'apikey': st.secrets['SUPABASE_ANON_KEY'], 'Content-Type': 'application/json'}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    if prefer:
        headers['Prefer'] = prefer
    try:
        resp = requests.request(method, st.secrets['SUPABASE_URL'].rstrip('/') + path,
                                headers=headers, json=body, timeout=20)
    except requests.RequestException:
        raise RuntimeError('서버에 연결하지 못했어요. 인터넷 연결을 확인하고 다시 시도해 주세요.')
    if not resp.ok:
        if resp.status_code == 401:
            raise RuntimeError('로그인이 만료되었어요. 로그아웃 후 다시 로그인해 주세요.')
        try:
            data = resp.json()
            message = data.get('msg') or data.get('message') or data.get('error_description') or '요청 실패'
        except ValueError:
            message = '요청 실패'
        raise RuntimeError(f'저장소 요청 오류 ({resp.status_code}): {message}')
    return resp.json() if resp.content else None


def load():
    auth = st.session_state.auth
    rows = api('GET', '/rest/v1/study_plans?select=payload,version&user_id=eq.' + auth['user']['id'], auth['access_token'])
    if not rows:
        api('POST', '/rest/v1/study_plans', auth['access_token'],
            {'user_id': auth['user']['id'], 'payload': {'goals': []}, 'version': 0})
        return {'goals': []}, 0
    return rows[0]['payload'], rows[0]['version']


def save(payload, version):
    auth = st.session_state.auth
    rows = api('PATCH', f"/rest/v1/study_plans?user_id=eq.{auth['user']['id']}&version=eq.{version}",
               auth['access_token'], {'payload': payload, 'version': version+1}, 'return=representation')
    if not rows:
        raise RuntimeError('다른 창에서 기록이 변경되었어요. 화면을 새로고침하고 다시 입력해 주세요.')
    st.session_state.notice = '저장했어요 🌱'
    st.rerun()


def goal_form(today, old=None):
    kind = st.radio('종류', ['책', '인강'], index=0 if not old or old['kind']=='책' else 1, horizontal=True)
    name = st.text_input('이름', value=old['name'] if old else '', max_chars=60, placeholder='책 또는 강의 이름')
    total = st.number_input('전체 목표량 · 쪽 / 강', min_value=1, max_value=100000,
                            value=int(old['total']) if old else 100, step=1)
    start = date.fromisoformat(old['start']) if old else today
    end = st.date_input('완료일', value=date.fromisoformat(old['end']) if old else today+timedelta(days=14))
    selected = st.multiselect('공부 요일', WEEKDAYS,
                             default=[WEEKDAYS[i] for i in old['weekdays']] if old else WEEKDAYS[:5])
    if st.form_submit_button('저장' if old else '시작하기', use_container_width=True):
        weekdays = [WEEKDAYS.index(w) for w in selected]
        if not name.strip():
            st.error('이름을 입력해 주세요.')
        elif end < max(start, today):
            st.error('완료일은 오늘 이후로 정해 주세요.')
        elif not study_days(max(start, today), end, weekdays):
            st.error('공부할 날이 없어요. 완료일이나 요일을 바꿔 주세요.')
        elif old and total < sum(old['logs'].values()):
            st.error('전체 목표량은 완료한 양보다 작을 수 없어요.')
        elif old and any(date.fromisoformat(d) > end for d, v in old['logs'].items() if v):
            st.error('완료일에 기존 기록 날짜도 포함해 주세요.')
        else:
            return {'id': old['id'] if old else uuid.uuid4().hex, 'kind': kind, 'name': name.strip(),
                    'total': int(total), 'start': start.isoformat(), 'end': end.isoformat(),
                    'weekdays': weekdays, 'logs': copy.deepcopy(old['logs']) if old else {}}
    return None


def main():
    st.set_page_config(page_title='끝까지 · 책과 인강', page_icon='🌱', layout='centered', initial_sidebar_state='collapsed')
    st.markdown("""<style>
    :root{color-scheme:light;}
    .stApp,[data-testid="stAppViewContainer"]{background:#F6F8FC!important;color:#202D45!important;}
    .block-container{max-width:490px;padding:1.1rem 1rem 2rem!important;}
    [data-testid="stHeader"]{background:transparent;}
    h1,h2,h3,p,label{color:#202D45;}
    h1{font-size:1.5rem!important;padding:0!important;}
    div[data-testid="stVerticalBlock"]{gap:.55rem;}
    [data-testid="stWidgetLabel"] p{color:#202D45!important;font-size:.86rem;}
    [data-baseweb="select"]>div,[data-baseweb="input"],[data-baseweb="input"]>div,
    [data-baseweb="base-input"], [data-baseweb="textarea"]{background:#FFFFFF!important;color:#202D45!important;border-color:#CBD5E1!important;}
    [data-baseweb="select"] span,[data-baseweb="select"] div,input,textarea{color:#202D45!important;-webkit-text-fill-color:#202D45!important;}
    input::placeholder{color:#778399!important;-webkit-text-fill-color:#778399!important;}
    [data-baseweb="popover"],[role="listbox"],[role="option"]{background:#fff!important;color:#202D45!important;}
    [data-testid="stNumberInput"] button{background:#EFF3FA!important;color:#202D45!important;}
    [data-testid="stNumberInput"] svg,[data-baseweb="select"] svg{fill:#44536C!important;}
    [data-testid="stForm"]{background:white;border:1px solid #E1E7F0;border-radius:18px;padding:14px;}
    .stButton>button,.stFormSubmitButton>button{background:#4263EB!important;border:0!important;color:#fff!important;border-radius:12px;min-height:44px;}
    .stButton>button p,.stFormSubmitButton>button p{color:#fff!important;}
    [data-testid="stExpander"]{background:white!important;border:1px solid #E1E7F0!important;border-radius:14px;}
    [data-testid="stExpander"] summary{background:white!important;color:#202D45!important;}
    [data-testid="stExpander"] summary p{color:#202D45!important;}
    [data-testid="stCaptionContainer"] p{color:#5B6A82!important;}
    .today-card{background:#EDF1FF;border:1px solid #DAE2FF;padding:18px;border-radius:20px;}
    .today-label{font-size:13px;color:#435579;}
    .today-number{font-size:38px;font-weight:800;color:#2949C7;line-height:1.4;}
    .today-detail{font-size:13px;color:#435579;}

    /* 입력 요소 자신과 내부 래퍼 모두 흰색으로 지정 */
    [data-testid="stTextInput"] input,
    [data-testid="stNumberInput"] input,
    [data-testid="stDateInput"] input,
    [data-testid="stTextArea"] textarea,
    [data-baseweb="input"], [data-baseweb="base-input"],
    [data-baseweb="select"] > div,
    [data-baseweb="select"] > div > div {
        background-color:#FFFFFF!important;color:#202D45!important;
        -webkit-text-fill-color:#202D45!important;color-scheme:light!important;
    }
    [data-testid="stTextInputRootElement"],
    [data-testid="stDateInput"] [data-baseweb],
    [data-testid="stNumberInputContainer"]{background:#FFFFFF!important;color:#202D45!important;}
    [data-baseweb="calendar"], [data-baseweb="calendar"] div,
    [data-baseweb="calendar"] button,
    [data-baseweb="calendar"] [role="gridcell"],
    [data-baseweb="popover"] > div,
    [role="listbox"], [role="option"]{
        background-color:#FFFFFF!important;color:#202D45!important;
        -webkit-text-fill-color:#202D45!important;color-scheme:light!important;
    }
    [data-baseweb="calendar"] [aria-selected="true"]{
        background:#4263EB!important;color:#FFFFFF!important;-webkit-text-fill-color:#FFFFFF!important;
    }
    [data-baseweb="tag"]{background:#E9EEFF!important;}
    [data-baseweb="tag"] span{color:#2949C7!important;}
    [data-testid="stForm"]{padding:12px!important;}
    [data-testid="stCaptionContainer"] p{font-size:12px!important;}
    </style>""", unsafe_allow_html=True)
    st.title('끝까지 🌱')

    try:
        configured = bool(st.secrets.get('SUPABASE_URL') and st.secrets.get('SUPABASE_ANON_KEY'))
    except Exception:
        configured = False
    st.session_state.cloud_storage = configured

    if 'auth' not in st.session_state:
        with st.form('auth_form'):
            email = st.text_input('내 아이디', max_chars=40, placeholder='예: study123')
            password = st.text_input('비밀번호', type='password', help='가입 시 8자 이상을 권장해요.')
            action = st.radio('접속', ['로그인', '회원가입'], horizontal=True, label_visibility='collapsed')
            submitted = st.form_submit_button('시작하기', use_container_width=True)
        st.caption('이메일 없이 사용해요 · 비밀번호 8자 이상')
        if submitted:
            if not email.strip() or not password:
                st.warning('아이디와 비밀번호를 입력해 주세요.')
            elif not all(c.isascii() and (c.isalnum() or c in '_-') for c in email.strip()) or len(email.strip()) < 3:
                st.warning('아이디는 영문·숫자·밑줄·하이픈으로 3~40자 입력해 주세요.')
            elif action == '회원가입' and len(password) < 8:
                st.warning('비밀번호는 8자 이상으로 정해 주세요.')
            else:
                try:
                    path = '/auth/v1/signup' if action=='회원가입' else '/auth/v1/token?grant_type=password'
                    result = api('POST', path, body={'email': (email.strip().lower() + '@study.invalid') if configured else email.strip().lower(), 'password': password})
                    if result.get('access_token'):
                        st.session_state.auth = result
                        st.rerun()
                    else:
                        st.warning('관리자가 Supabase의 Confirm email 설정을 꺼야 아이디 가입을 사용할 수 있어요. 이 아이디에는 인증 메일을 받을 수 없어요.')
                except RuntimeError as exc:
                    st.error(str(exc))
        return
    today = datetime.now(ZoneInfo('Asia/Seoul')).date()
    if st.session_state.get('notice'):
        st.toast(st.session_state.pop('notice'))
    try:
        # 장시간 열린 앱은 access token 갱신; refresh token은 세션 메모리에만 보관.
        auth = st.session_state.auth
        if auth.get('expires_at', 0) and auth['expires_at'] < datetime.now().timestamp()+90:
            st.session_state.auth = api('POST', '/auth/v1/token?grant_type=refresh_token',
                                        body={'refresh_token': auth['refresh_token']})
        payload, version = load()
        goals = payload['goals']
        if goals:
            ids = [g['id'] for g in goals]
            selected = st.selectbox('내 목표', ids, format_func=lambda x: next(g['name'] for g in goals if g['id']==x),
                                    label_visibility='collapsed')
            goal = next(g for g in goals if g['id']==selected)
            unit = '쪽' if goal['kind']=='책' else '강'
            target, remaining, days, future = plan(goal, today)
            completed = goal['total']-remaining
            today_done = int(goal['logs'].get(today.isoformat(), 0))
            left = max(0, target-today_done)
            if remaining == 0:
                heading, big, detail = '목표 완주!', '완료 🎉', '끝까지 해냈어요. 새로운 목표를 시작해 보세요.'
            elif today > date.fromisoformat(goal['end']) or not days:
                heading, big, detail = '계획 조정이 필요해요', '날짜 변경', '아래 관리에서 완료일이나 공부 요일을 바꿔 주세요.'
            elif today < date.fromisoformat(goal['start']):
                heading, big, detail = '시작 예정', goal['start'][5:], '정한 날짜부터 오늘 할 분량을 알려 드려요.'
            elif today.weekday() not in goal['weekdays']:
                heading, big, detail = '오늘은 쉬는 날', '쉬어 가요 ☁️', '미리 공부했다면 아래에 기록해도 좋아요.'
            elif left == 0:
                heading, big, detail = '오늘 목표 달성', '잘했어요 ✓', f'오늘 {today_done}{unit} 완료 · 더 공부해도 기록할 수 있어요.'
            else:
                heading, big, detail = '오늘 더 할 분량', f'{left:,}{unit}', f'오늘 목표 {target:,}{unit} · 오늘 완료 {today_done:,}{unit}'
            st.markdown(f'<div class="today-card"><div class="today-label">{html.escape(heading)}</div><div class="today-number">{html.escape(big)}</div><div class="today-detail">{html.escape(detail)}</div></div>', unsafe_allow_html=True)
            st.progress(completed/goal['total'], text=f"전체 {completed:,} / {goal['total']:,}{unit} · {completed/goal['total']:.0%}")
            st.caption(f"{goal['end'][5:]}까지 · 남은 {remaining:,}{unit} · 공부할 날 {len(days)}일")
            with st.form('progress_'+selected):
                amount = st.number_input(f'오늘 공부한 양 ({unit})', min_value=0,
                                         max_value=int(remaining+today_done), value=today_done, step=1,
                                         help='오늘 공부한 양의 합계예요. 다시 저장하면 기존 숫자를 바꿔요.')
                if st.form_submit_button('기록 저장', use_container_width=True):
                    if today < date.fromisoformat(goal['start']) or today > date.fromisoformat(goal['end']):
                        st.warning('오늘이 포함되도록 목표 기간을 먼저 수정해 주세요.')
                    else:
                        goal['logs'][today.isoformat()] = int(amount)
                        save(payload, version)
            with st.expander('기록 확인 · 수정'):

                recent = sorted(goal['logs'].items(), reverse=True)[:7]
                if recent:
                    for d, v in recent:
                        st.write(f"{d[5:]}　·　{v:,}{unit}")
                else:
                    st.caption('아직 기록이 없어요. 첫 공부를 기록해 보세요.')
                if future:
                    d, v = next(iter(future.items()))
                    st.caption(f'다음 공부일 {d[5:]} · 예정 {v}{unit} (실제 진도에 따라 조정)')
                earliest = date.fromisoformat(goal['start'])
                latest = min(today, date.fromisoformat(goal['end']))
                if earliest <= latest:
                    with st.form('edit_logs_'+selected):
                        log_day = st.date_input('수정할 기록 날짜', value=latest, min_value=earliest, max_value=latest)

                        revised = st.number_input(f'그날 공부한 총분량 ({unit})', min_value=0, max_value=goal['total'], value=0, step=1)
                        confirm = st.checkbox('선택한 날짜 기록을 위 숫자로 바꿀게요')
                        if st.form_submit_button('과거 기록 수정'):
                            other = sum(v for k,v in goal['logs'].items() if k != log_day.isoformat())
                            if not confirm:
                                st.warning('기록 변경 확인에 체크해 주세요.')
                            elif other + revised > goal['total']:
                                st.error('총 완료량이 전체 목표 분량을 초과해요.')
                            else:
                                goal['logs'][log_day.isoformat()] = int(revised)
                                save(payload, version)
            with st.expander('목표 수정'):
                with st.form('edit_goal_'+selected):
                    updated = goal_form(today, goal)
                if updated:
                    payload['goals'] = [updated if g['id']==selected else g for g in goals]
                    save(payload, version)
        with st.expander('＋ 새 목표 등록', expanded=not bool(goals)):
            with st.form('new_goal'):
                new = goal_form(today)
            if new:
                payload['goals'].append(new)
                save(payload, version)
    except RuntimeError as exc:
        st.error(str(exc))
        st.caption('저장 실패 시 입력은 서버에 반영되지 않을 수 있어요. 연결을 확인하고 다시 시도해 주세요.')
    with st.expander('계정 · 백업'):
        if 'payload' in locals():
            st.download_button('내 기록 백업 (JSON)', json.dumps(payload, ensure_ascii=False, indent=2), 'study_backup.json', 'application/json', use_container_width=True)
        if not configured:
            st.warning('임시 저장 중 · 재배포 시 삭제될 수 있어요. 중요한 기록은 백업하세요.')
        st.caption('분량 기준 계산 · 강의 길이와 난이도는 미반영')
        st.caption('이메일을 받지 않아 비밀번호 복구는 지원하지 않아요.')
        if st.button('로그아웃', use_container_width=True):
            token = st.session_state.auth.get('access_token')
            try:
                api('POST', '/auth/v1/logout', token)
            except RuntimeError:
                pass
            st.session_state.clear()
            st.rerun()


if __name__ == '__main__':
    main()
