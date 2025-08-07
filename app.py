import re
import io
import tempfile
from datetime import datetime
from collections import Counter

import streamlit as st
import pandas as pd

# Intenta cargar matplotlib; si falta, avisa claramente
try:
    import matplotlib.pyplot as plt
except ModuleNotFoundError:
    st.error("Falta 'matplotlib'. Asegúrate de que 'requirements.txt' incluya: matplotlib")
    st.stop()

# PDF
try:
    from fpdf import FPDF
except ModuleNotFoundError:
    st.error("Falta 'fpdf'. Asegúrate de que 'requirements.txt' incluya: fpdf")
    st.stop()

# ---------------------------
# Configuración general
# ---------------------------
st.set_page_config(page_title="Auditoría de Acceso Lógico", layout="wide")

st.title("🔐 Auditoría de Acceso Lógico en Linux – ISO/IEC 27001")
st.markdown(
    "Esta aplicación analiza **usuarios del sistema**, detecta **UIDs duplicados**, "
    "lee **intentos fallidos de acceso SSH** y evalúa el estado de **MFA**. "
    "Puedes subir archivos reales o usar datos de ejemplo y **exportar un PDF** con el informe."
)

# ---------------------------
# Datos de ejemplo
# ---------------------------
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
# Falta AuthenticationMethods → MFA parcial
"""

# ---------------------------
# Sidebar: entradas
# ---------------------------
with st.sidebar:
    st.header("⚙️ Entradas")
    use_examples = st.toggle("Usar datos de ejemplo", value=True)
    passwd_file = st.file_uploader("`/etc/passwd`", type=["txt", "conf", "passwd"])
    logs_file = st.file_uploader("Logs SSH (journalctl/auth.log)", type=["log", "txt"])
    sshd_file = st.file_uploader("`/etc/ssh/sshd_config`", type=["conf", "txt"])

def get_text(uploaded_file, example_text):
    if use_examples or not uploaded_file:
        return example_text
    return uploaded_file.read().decode("utf-8", errors="ignore")

passwd_text = get_text(passwd_file, EXAMPLE_PASSWD)
logs_text   = get_text(logs_file,   EXAMPLE_LOGS)
sshd_text   = get_text(sshd_file,   EXAMPLE_SSHD)

# ---------------------------
# Parsers
# ---------------------------
def parse_passwd(text: str) -> pd.DataFrame:
    rows = []
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) >= 7:
            user, _, uid, gid, gecos, home, shell = parts[:7]
            try:
                uid = int(uid)
            except:
                uid = None
            rows.append({"user": user, "uid": uid, "home": home, "shell": shell})
    return pd.DataFrame(rows)

LOG_PAT = re.compile(
    r"(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2}).*sshd.*Failed password.*for\s+(?:invalid user\s+)?(?P<user>[A-Za-z0-9._-]+)\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)",
    re.IGNORECASE,
)
MONTHS = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split()

def month_to_num(m): 
    return MONTHS.index(m)+1 if m in MONTHS else 1

def parse_failed_logins(text: str) -> pd.DataFrame:
    rows = []
    year = datetime.now().year
    for line in text.splitlines():
        m = LOG_PAT.search(line)
        if m:
            d = m.groupdict()
            try:
                dt = datetime(
                    year, month_to_num(d["mon"]), int(d["day"]),
                    int(d["time"][0:2]), int(d["time"][3:5]), int(d["time"][6:8])
                )
            except Exception:
                dt = None
            rows.append({
                "datetime": dt, "user": d["user"], "ip": d["ip"], "raw": line.strip()
            })
    return pd.DataFrame(rows)

def parse_sshd_config(text: str) -> dict:
    lines = [l.strip() for l in text.splitlines() if l.strip() and not l.strip().startswith("#")]
    d = {l.split()[0].lower(): l for l in lines if l.split()}
    has_auth_methods = any(k == "authenticationmethods" and ("," in v.lower() or "publickey" in v.lower()) for k, v in d.items())
    challenge_yes    = "challengeresponseauthentication" in d and "yes" in d["challengeresponseauthentication"].lower()
    usepam_yes       = "usepam" in d and "yes" in d["usepam"].lower()

    if has_auth_methods:
        status = "full"
    elif challenge_yes and usepam_yes:
        status = "partial"
    else:
        status = "no"
    return {"status": status, "lines": lines}

# ---------------------------
# Procesamiento
# ---------------------------
users_df = parse_passwd(passwd_text)
fails_df = parse_failed_logins(logs_text)
sshd_info = parse_sshd_config(sshd_text)

dup_map = {}
if not users_df.empty:
    counts = Counter(users_df["uid"])
    for uid, c in counts.items():
        if c and c > 1:
            dup_map[uid] = list(users_df.loc[users_df["uid"] == uid, "user"].values)

mfa_status = sshd_info["status"]
mfa_label = {
    "full":    "MFA correctamente configurado (AuthenticationMethods).",
    "partial": "MFA parcialmente configurado (ChallengeResponseAuthentication/UsePAM sin AuthenticationMethods).",
    "no":      "MFA NO configurado."
}[mfa_status]

# Riesgo simple
risk_score = 0
risk_score += 2 if len(dup_map) > 0 else 0
risk_score += 2 if len(fails_df) >= 5 else (1 if len(fails_df) > 0 else 0)
risk_score += 0 if mfa_status == "full" else (1 if mfa_status == "partial" else 3)
risk_level = "ALTO" if risk_score >= 5 else ("MEDIO" if risk_score >= 3 else "BAJO")

# ---------------------------
# Salida visual
# ---------------------------
st.markdown("## 👥 Usuarios del sistema")
st.dataframe(users_df, use_container_width=True)

st.markdown("## 🔁 UIDs duplicados (cuentas compartidas)")
if dup_map:
    for uid, names in dup_map.items():
        st.error(f"UID **{uid}** compartido por: **{', '.join(names)}**")
else:
    st.success("No se detectaron cuentas con UID compartido.")

st.markdown("## 🚨 Intentos fallidos de acceso SSH")
if fails_df.empty:
    st.info("No se detectaron intentos fallidos en los logs.")
else:
    st.dataframe(fails_df[["datetime", "user", "ip", "raw"]], use_container_width=True)

    # Gráfico por fecha (si hay timestamps)
    if fails_df["datetime"].notna().any():
        df_plot = fails_df.dropna(subset=["datetime"]).copy()
        df_plot["date"] = df_plot["datetime"].dt.date
        agg = df_plot.groupby("date").size().reset_index(name="failed")
        fig, ax = plt.subplots()
        ax.bar(agg["date"].astype(str), agg["failed"])
        ax.set_title("Intentos fallidos por día")
        ax.set_xlabel("Fecha")
        ax.set_ylabel("Intentos")
        st.pyplot(fig)
    else:
        fig = None

st.markdown("## 🔐 Estado del MFA")
if mfa_status == "full":
    st.success(mfa_label)
elif mfa_status == "partial":
    st.warning(mfa_label)
else:
    st.error(mfa_label)

st.markdown("## 🧮 Evaluación de Riesgo")
col1, col2 = st.columns(2)
with col1:
    st.metric("Nivel de riesgo", risk_level)
with col2:
    st.metric("Puntaje", risk_score)

st.markdown("## 📌 Conclusiones")
conclusions = []
conclusions.append("• Se detectó un UID duplicado (posible cuenta compartida)." if dup_map else "• No se detectaron UIDs duplicados.")
conclusions.append("• Existen intentos de acceso fallido." if not fails_df.empty else "• No se detectaron intentos de acceso fallido.")
conclusions.append("• " + mfa_label)
st.write("\n".join(conclusions))

# ---------------------------
# Exportar PDF
# ---------------------------
def build_pdf() -> bytes:
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Arial", "B", 14)
    pdf.cell(0, 10, "Informe de Auditoria de Acceso Logico (ISO/IEC 27001)", ln=True)
    pdf.set_font("Arial", "", 11)
    pdf.cell(0, 8, f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
    pdf.ln(2)

    # Resumen
    pdf.set_font("Arial", "B", 12)
    pdf.cell(0, 8, "Resumen:", ln=True)
    pdf.set_font("Arial", "", 11)
    pdf.multi_cell(0, 7,
        f"- UIDs duplicados: {'SI' if dup_map else 'NO'}\n"
        f"- Intentos fallidos: {len(fails_df)}\n"
        f"- MFA: {mfa_label}\n"
        f"- Riesgo: {risk_level} (puntaje {risk_score})"
    )

    # Usuarios (muestra)
    pdf.set_font("Arial", "B", 12)
    pdf.ln(2)
    pdf.cell(0, 8, "Usuarios (muestra):", ln=True)
    pdf.set_font("Arial", "", 11)
    for _, r in users_df.head(20).iterrows():
        pdf.cell(0, 6, f"- {r['user']} (UID {r['uid']})", ln=True)

    # Duplicados
    if dup_map:
        pdf.ln(2)
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 8, "UIDs duplicados:", ln=True)
        pdf.set_font("Arial", "", 11)
        for uid, names in dup_map.items():
            pdf.cell(0, 6, f"- UID {uid}: {', '.join(names)}", ln=True)

    # Intentos fallidos (muestra)
    if not fails_df.empty:
        pdf.ln(2)
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 8, "Intentos fallidos (muestra):", ln=True)
        pdf.set_font("Arial", "", 11)
        for _, r in fails_df.head(10).iterrows():
            dt = r["datetime"].strftime("%Y-%m-%d %H:%M:%S") if pd.notna(r["datetime"]) else "s/f"
            pdf.cell(0, 6, f"- {dt} | user {r['user']} | ip {r['ip']}", ln=True)

    # Gráfico (si existe)
    img_tmp = None
    if 'fig' in globals() and plt.get_fignums():
        # Guarda el último grafico mostrado
        img_tmp = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
        plt.savefig(img_tmp.name, bbox_inches="tight")
        pdf.add_page()
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 8, "Grafico: Intentos fallidos por dia", ln=True)
        pdf.image(img_tmp.name, w=180)

    # Salida como bytes
    pdf_bytes = pdf.output(dest="S").encode("latin-1")
    return pdf_bytes

st.markdown("## 🧾 Exportar informe")
if st.button("Generar PDF"):
    try:
        pdf_bytes = build_pdf()
        st.download_button(
            "Descargar informe PDF",
            data=pdf_bytes,
            file_name="informe_auditoria_logica.pdf",
            mime="application/pdf"
        )
    except Exception as e:
        st.error(f"No se pudo generar el PDF: {e}")