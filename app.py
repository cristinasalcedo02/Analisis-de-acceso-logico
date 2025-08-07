import re
import io
from datetime import datetime, timedelta
from collections import Counter

import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
from fpdf import FPDF

st.set_page_config(page_title="Auditoría de Acceso Lógico - ISO/IEC 27001", layout="wide")

# =========================
# Utilidades de parsing
# =========================
PASSWD_COLS = ["user","x","uid","gid","gecos","home","shell"]

EXAMPLE_PASSWD = """root:x:0:0:root:/root:/bin/bash
carlos:x:1000:1000::/home/carlos:/bin/bash
paola:x:1001:1001::/home/paola:/bin/bash
juan:x:1002:1002::/home/juan:/bin/bash
pedro:x:1003:1003::/home/pedro:/bin/bash
maria:x:1003:1004::/home/maria:/bin/bash
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
"""

EXAMPLE_LOGS = """Aug  7 10:15:01 server sshd[1234]: Failed password for invalid user guest from 192.168.1.10 port 2222 ssh2
Aug  7 10:20:22 server sshd[1235]: Failed password for admin from 192.168.1.11 port 2223 ssh2
Aug  7 11:12:44 server sshd[1236]: Failed password for juan from 192.168.1.20 port 2224 ssh2
"""

EXAMPLE_SSHD = """# sshd_config ejemplo
Port 22
PasswordAuthentication yes
ChallengeResponseAuthentication yes
UsePAM yes
# Nota: Falta AuthenticationMethods publickey,password (MFA parcial)
"""

def parse_passwd(text:str) -> pd.DataFrame:
    rows = []
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"): 
            continue
        parts = line.split(":")
        if len(parts) >= 7:
            row = dict(zip(PASSWD_COLS, parts[:7]))
            # convertir uid/gid a int si se puede
            for k in ("uid","gid"):
                try:
                    row[k] = int(row[k])
                except:
                    row[k] = None
            rows.append(row)
    df = pd.DataFrame(rows, columns=["user","uid","gid","home","shell"])
    return df

LOG_PATTERNS = [
    # journalctl/syslog típico
    re.compile(r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2}).*sshd.*Failed password.*for\s+(?:invalid user\s+)?(?P<user>[A-Za-z0-9._-]+)\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)"),
    # auth.log variantes
    re.compile(r".*Failed password.*for\s+(?:invalid user\s+)?(?P<user>[A-Za-z0-9._-]+)\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+).*(?P<time>\d{2}:\d{2}:\d{2})?")
]

def month_to_num(mon:str)->int:
    months = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split()
    return months.index(mon)+1 if mon in months else 1

def parse_failed_logins(text:str) -> pd.DataFrame:
    rows = []
    for line in text.splitlines():
        for pat in LOG_PATTERNS:
            m = pat.search(line)
            if m:
                d = m.groupdict()
                # construir fecha si hay mes/día/hora
                dt = None
                if "mon" in d and d["mon"] and "day" in d and d["day"] and "time" in d and d["time"]:
                    now = datetime.now()
                    try:
                        dt = datetime(now.year, month_to_num(d["mon"]), int(d["day"]))
                        hh,mm,ss = d["time"].split(":")
                        dt = dt.replace(hour=int(hh), minute=int(mm), second=int(ss))
                    except:
                        dt = None
                rows.append({
                    "datetime": dt,
                    "user": d.get("user","unknown"),
                    "ip": d.get("ip","unknown"),
                    "raw": line.strip()
                })
                break
    df = pd.DataFrame(rows)
    if "datetime" in df and df["datetime"].notna().any():
        df = df.sort_values("datetime")
    return df

def parse_sshd_config(text:str) -> dict:
    cfg = {}
    lines = [l.strip() for l in text.splitlines() if l.strip() and not l.strip().startswith("#")]
    for l in lines:
        key = l.split()[0]
        cfg[key] = l
    # criterios MFA
    has_auth_methods = any(
        k.lower()=="authenticationmethods" and ("," in v.lower() or "publickey" in v.lower())
        for k,v in ((key, cfg[key]) for key in cfg)
    )
    challenge_yes = any(k.lower()=="challengeresponseauthentication" and "yes" in cfg[k].lower() for k in cfg)
    use_pam_yes = any(k.lower()=="usepam" and "yes" in cfg[k].lower() for k in cfg)
    status = "no"
    if has_auth_methods:
        status = "full"
    elif challenge_yes and use_pam_yes:
        status = "partial"
    return {"status": status, "lines": lines}

def score_risk(dup_uids:int, failed:int, mfa_status:str) -> tuple[str,int]:
    # puntuación simple
    score = 0
    score += 2 if dup_uids>0 else 0
    score += 2 if failed>=5 else (1 if failed>0 else 0)
    score += 0 if mfa_status=="full" else (1 if mfa_status=="partial" else 3)
    if score >=5: level="ALTO"
    elif score>=3: level="MEDIO"
    else: level="BAJO"
    return level, score

def make_pdf(summary:dict, users_df:pd.DataFrame, dup_map:dict, fails_df:pd.DataFrame) -> bytes:
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "Informe de Auditoria de Acceso Logico (ISO/IEC 27001)", ln=True)
    pdf.set_font("Arial", size=11)
    pdf.multi_cell(0, 8, f"""Conclusiones:
- {'Se detectaron UIDs duplicados' if summary['dup_count']>0 else 'No se detectaron UIDs duplicados'}.
- {'Existen intentos fallidos de acceso SSH' if summary['failed_count']>0 else 'No hay intentos fallidos registrados'}.
- MFA: {summary['mfa_human']}.
- Nivel de Riesgo: {summary['risk_level']} (puntaje {summary['risk_score']}/7).""")
    pdf.ln(2)
    pdf.set_font("Arial","B",12)
    pdf.cell(0,8,"Usuarios (muestra):",ln=True)
    pdf.set_font("Arial",size=10)
    for _,r in users_df.head(15).iterrows():
        pdf.cell(0,6,f"- {r['user']} (UID {r['uid']})",ln=True)
    if dup_map:
        pdf.ln(2)
        pdf.set_font("Arial","B",12)
        pdf.cell(0,8,"UIDs duplicados:",ln=True)
        pdf.set_font("Arial",size=10)
        for uid, names in dup_map.items():
            pdf.cell(0,6,f"- UID {uid}: {', '.join(names)}",ln=True)
    if not fails_df.empty:
        pdf.ln(2)
        pdf.set_font("Arial","B",12)
        pdf.cell(0,8,"Intentos fallidos (muestra):",ln=True)
        pdf.set_font("Arial",size=10)
        for _,r in fails_df.head(10).iterrows():
            dt = r['datetime'].strftime("%Y-%m-%d %H:%M:%S") if pd.notna(r['datetime']) else "s/f"
            pdf.cell(0,6,f"- {dt} | user {r['user']} | ip {r['ip']}",ln=True)
    buf = io.BytesIO()
    pdf.output(buf)
    return buf.getvalue()

# =========================
# UI
# =========================
st.title("🔐 Auditoría de Acceso Lógico – ISO/IEC 27001")
st.caption("Sube archivos reales o usa datos de ejemplo. Se analizan UIDs duplicados, intentos fallidos de SSH y estado del MFA.")

with st.sidebar:
    st.header("⚙️ Entrada de datos")
    use_examples = st.toggle("Usar datos de ejemplo", value=True)
    passwd_file = st.file_uploader("`/etc/passwd`", type=["txt","conf","passwd"])
    logs_file   = st.file_uploader("Logs SSH (journalctl/auth.log)", type=["log","txt"])
    sshd_file   = st.file_uploader("`/etc/ssh/sshd_config`", type=["conf","txt"])

# Cargar datos
passwd_text = EXAMPLE_PASSWD if (use_examples or not passwd_file) else passwd_file.read().decode("utf-8", errors="ignore")
logs_text   = EXAMPLE_LOGS if (use_examples or not logs_file) else logs_file.read().decode("utf-8", errors="ignore")
sshd_text   = EXAMPLE_SSHD if (use_examples or not sshd_file) else sshd_file.read().decode("utf-8", errors="ignore")

# Procesar
users_df = parse_passwd(passwd_text)

dup_map = {}
if not users_df.empty:
    counts = Counter(users_df["uid"])
    for uid, c in counts.items():
        if c>1:
            dup_map[uid] = list(users_df.loc[users_df["uid"]==uid,"user"].values)
dup_count = len(dup_map)

fails_df = parse_failed_logins(logs_text)
failed_count = len(fails_df)

sshd_info = parse_sshd_config(sshd_text)
mfa_status = sshd_info["status"]
mfa_human = {"full":"MFA correctamente configurado (AuthenticationMethods)",
             "partial":"MFA parcialmente configurado (ChallengeResponseAuthentication/UsePAM sin AuthenticationMethods)",
             "no":"MFA NO configurado"}.get(mfa_status,"MFA NO configurado")

risk_level, risk_score = score_risk(dup_count, failed_count, mfa_status)

# =========================
# Resultados
# =========================
st.markdown("## 📋 Usuarios del sistema")
st.dataframe(users_df, use_container_width=True)

st.markdown("## 🔁 Detección de UIDs duplicados")
if dup_map:
    for uid, names in dup_map.items():
        st.error(f"UID **{uid}** compartido por: **{', '.join(names)}**")
else:
    st.success("No se detectaron cuentas con UID compartido.")

st.markdown("## 🚨 Intentos fallidos de acceso SSH")
if failed_count:
    st.dataframe(fails_df[["datetime","user","ip","raw"]], use_container_width=True)
    # Gráfica por día
    if fails_df["datetime"].notna().any():
        st.markdown("**Distribución por fecha (últimos eventos detectados):**")
        df_plot = fails_df.dropna(subset=["datetime"]).copy()
        df_plot["date"] = df_plot["datetime"].dt.date
        counts = df_plot.groupby("date").size().reset_index(name="failed")
        fig, ax = plt.subplots()
        ax.bar(counts["date"].astype(str), counts["failed"])
        ax.set_xlabel("Fecha")
        ax.set_ylabel("Intentos fallidos")
        ax.set_title("Intentos fallidos por día")
        st.pyplot(fig)
else:
    st.info("No se detectaron intentos fallidos en los logs proporcionados.")

st.markdown("## 🔐 Estado del MFA")
if mfa_status == "full":
    st.success(mfa_human)
elif mfa_status == "partial":
    st.warning(mfa_human)
else:
    st.error(mfa_human)

st.markdown("## 🧮 Evaluación de Riesgo")
st.metric("Nivel de riesgo", risk_level, help="Modelo simple basado en duplicados, accesos fallidos y MFA")
st.caption(f"Puntaje: {risk_score}/7 — Duplicados={dup_count}, Fallidos={failed_count}, MFA={mfa_status}")

st.markdown("## 📌 Conclusión del análisis técnico")
bullets = []
bullets.append("• Se detectó un UID duplicado (posible cuenta compartida)." if dup_count>0 else "• No se detectaron UIDs duplicados.")
bullets.append("• Existen múltiples intentos de acceso fallido sin respuesta de bloqueo." if failed_count>0 else "• No se detectaron intentos de acceso fallido recientes.")
bullets.append("• MFA está implementado parcialmente." if mfa_status=='partial' else ("• MFA no está configurado." if mfa_status=='no' else "• MFA correctamente configurado."))
st.write("\n".join(bullets))

# =========================
# Exportar PDF
# =========================
st.markdown("## 🧾 Exportar informe")
if st.button("Generar PDF"):
    pdf_bytes = make_pdf(
        summary={
            "dup_count": dup_count,
            "failed_count": failed_count,
            "mfa_human": mfa_human,
            "risk_level": risk_level,
            "risk_score": risk_score
        },
        users_df=users_df,
        dup_map=dup_map,
        fails_df=fails_df
    )
    st.download_button(
        label="Descargar informe PDF",
        data=pdf_bytes,
        file_name="informe_auditoria_logica.pdf",
        mime="application/pdf"
    )
