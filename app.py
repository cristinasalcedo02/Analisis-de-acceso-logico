import re
import io
import tempfile
from datetime import datetime
from collections import Counter

import streamlit as st
import pandas as pd

# --- Dependencias que deben estar en requirements.txt ---
try:
    import matplotlib.pyplot as plt
except ModuleNotFoundError:
    st.error("Falta 'matplotlib'. Asegúrate de que requirements.txt incluya: matplotlib")
    st.stop()

try:
    from fpdf import FPDF
except ModuleNotFoundError:
    st.error("Falta 'fpdf'. Asegúrate de que requirements.txt incluya: fpdf")
    st.stop()

# ========== Configuración ==========
st.set_page_config(page_title="Auditoría de Acceso Lógico", page_icon="🔐", layout="wide")
st.title("🔐 Auditoría de Acceso Lógico en Linux – ISO/IEC 27001")
st.write(
    "Sube los **archivos reales** del sistema para ejecutar el análisis:\n"
    "- `/etc/passwd`\n"
    "- Logs SSH (por ejemplo `auth.log` o salida de `journalctl`)\n"
    "- `/etc/ssh/sshd_config`\n\n"
    "La app detectará **UIDs duplicados**, intentos fallidos de acceso y el estado de **MFA**, "
    "mostrará **gráficos** y permitirá **exportar un informe PDF**."
)

with st.sidebar:
    st.header("📂 Cargar archivos")
    passwd_file = st.file_uploader("Archivo `/etc/passwd`", type=["txt", "conf", "passwd"])
    logs_file   = st.file_uploader("Logs SSH (auth.log/journalctl)", type=["log", "txt"])
    sshd_file   = st.file_uploader("Archivo `/etc/ssh/sshd_config`", type=["conf", "txt"])

# Si faltan archivos, no mostramos nada más
if not (passwd_file and logs_file and sshd_file):
    st.warning("⚠️ Sube **los tres archivos** para iniciar el análisis.")
    st.stop()

# ========== Lectura segura de archivos ==========
def read_text(uploaded) -> str:
    return uploaded.read().decode("utf-8", errors="ignore")

passwd_text = read_text(passwd_file)
logs_text   = read_text(logs_file)
sshd_text   = read_text(sshd_file)

# ========== Parsers ==========
def parse_passwd(text: str) -> pd.DataFrame:
    """
    /etc/passwd -> DataFrame con columnas: user, uid, home, shell
    """
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

# Ej: "Aug  7 10:15:01 server sshd[1234]: Failed password for admin from 192.168.1.11 port 2223 ssh2"
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
            rows.append({"datetime": dt, "user": d["user"], "ip": d["ip"], "raw": line.strip()})
    return pd.DataFrame(rows)

def parse_sshd_config(text: str) -> dict:
    """
    Determina MFA:
      - full     -> AuthenticationMethods presente y combinando factores (ej: publickey,password)
      - partial  -> ChallengeResponseAuthentication yes y UsePAM yes, pero sin AuthenticationMethods
      - no       -> Nada de lo anterior
    """
    lines = [l.strip() for l in text.splitlines() if l.strip() and not l.strip().startswith("#")]
    # Diccionario normalizado por clave (lower)
    entries = {}
    for l in lines:
        toks = l.split()
        if not toks: 
            continue
        entries[toks[0].lower()] = l

    has_auth_methods = any(
        k == "authenticationmethods" and ("," in v.lower() or "publickey" in v.lower())
        for k, v in entries.items()
    )
    challenge_yes = "challengeresponseauthentication" in entries and "yes" in entries["challengeresponseauthentication"].lower()
    usepam_yes    = "usepam" in entries and "yes" in entries["usepam"].lower()

    if has_auth_methods:
        status = "full"
    elif challenge_yes and usepam_yes:
        status = "partial"
    else:
        status = "no"
    return {"status": status, "lines": lines}

# ========== Procesamiento ==========
users_df = parse_passwd(passwd_text)
fails_df = parse_failed_logins(logs_text)
sshd_info = parse_sshd_config(sshd_text)

# UIDs duplicados
dup_map = {}
if not users_df.empty:
    counts = Counter(users_df["uid"])
    for uid, c in counts.items():
        if c and c > 1:
            dup_map[uid] = list(users_df.loc[users_df["uid"] == uid, "user"].values)

# MFA
mfa_status = sshd_info["status"]
mfa_label = {
    "full":    "MFA correctamente configurado (AuthenticationMethods presente).",
    "partial": "MFA parcialmente configurado (ChallengeResponseAuthentication/UsePAM sin AuthenticationMethods).",
    "no":      "MFA NO configurado.",
}[mfa_status]

# Riesgo simple (puedes ajustar ponderaciones)
risk_score = 0
risk_score += 2 if len(dup_map) > 0 else 0
risk_score += 2 if len(fails_df) >= 5 else (1 if len(fails_df) > 0 else 0)
risk_score += 0 if mfa_status == "full" else (1 if mfa_status == "partial" else 3)
risk_level = "ALTO" if risk_score >= 5 else ("MEDIO" if risk_score >= 3 else "BAJO")

# ========== Salida ==========
st.subheader("👥 Usuarios del sistema")
st.dataframe(users_df, use_container_width=True)

st.subheader("🔁 UIDs duplicados (cuentas compartidas)")
if dup_map:
    for uid, names in dup_map.items():
        st.error(f"UID **{uid}** compartido por: **{', '.join(names)}**")
else:
    st.success("No se detectaron cuentas con UID compartido.")

st.subheader("🚨 Intentos fallidos de acceso SSH")
if fails_df.empty:
    st.info("No se detectaron intentos fallidos en los logs.")
else:
    st.dataframe(fails_df[["datetime", "user", "ip", "raw"]], use_container_width=True)

    # Gráfico por día si hay timestamps
    fig = None
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

st.subheader("🔑 Estado del MFA")
if mfa_status == "full":
    st.success(mfa_label)
elif mfa_status == "partial":
    st.warning(mfa_label)
else:
    st.error(mfa_label)

st.subheader("📊 Evaluación de riesgo")
c1, c2 = st.columns(2)
with c1: st.metric("Nivel de riesgo", risk_level)
with c2: st.metric("Puntaje", risk_score)

st.subheader("📌 Conclusiones")
conclusions = []
conclusions.append("• Se detectó un UID duplicado (posible cuenta compartida)." if dup_map else "• No se detectaron UIDs duplicados.")
conclusions.append("• Existen intentos de acceso fallido." if not fails_df.empty else "• No se detectaron intentos de acceso fallido.")
conclusions.append("• " + mfa_label)
st.write("\n".join(conclusions))

# ========== Exportar PDF ==========
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
    pdf.set_font("Arial", "B", 12); pdf.ln(2)
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

    # Gráfico si existe
    if plt.get_fignums():
        tmp = tempfile.NamedTemporaryFile(suffix=".png", delete=False)
        plt.savefig(tmp.name, bbox_inches="tight")
        pdf.add_page()
        pdf.set_font("Arial", "B", 12)
        pdf.cell(0, 8, "Grafico: Intentos fallidos por dia", ln=True)
        pdf.image(tmp.name, w=180)

    return pdf.output(dest="S").encode("latin-1")

st.subheader("🧾 Exportar informe")
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
