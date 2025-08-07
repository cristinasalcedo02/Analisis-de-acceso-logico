import streamlit as st

st.title("Auditoría de Acceso Lógico en Linux")

st.header("🔐 UIDs duplicados detectados")
st.warning("UID 1003 compartido por: pedro y maria")

st.header("👥 Usuarios del sistema")
usuarios = {
    "root": 0,
    "carlos": 1000,
    "paola": 1001,
    "juan": 1002,
    "pedro": 1003,
    "maria": 1003,
    "nobody": 65534
}
st.code("\n".join([f"- {u} (UID: {uid})" for u, uid in usuarios.items()]))

st.header("🚨 Intentos fallidos SSH")
st.error("guest desde 192.168.1.10
admin desde 192.168.1.11")

st.header("🟡 Estado del MFA")
st.warning("MFA parcialmente configurado. Falta directiva 'AuthenticationMethods'.")

st.header("📌 Conclusión")
st.markdown("""
- Se detectó un UID duplicado (posible cuenta compartida).  
- Existen múltiples intentos de acceso fallido sin respuesta de bloqueo.  
- MFA está implementado parcialmente.
""")
