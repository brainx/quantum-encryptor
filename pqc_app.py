# pqc_app.py
import streamlit as st
import logging
from pathlib import Path
import mimetypes  # For guessing download mime type
import re

# Import core logic and config
from crypto_config import cfg
import crypto_core as core
from ui_helpers import guess_decrypted_filename

# --- Basic Logging Setup ---
# Configure logging level and format
# Streamlit can sometimes interfere with basicConfig, setting level explicitly helps.
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - [%(module)s] - %(message)s",
)
logger = logging.getLogger(__name__)

# --- Streamlit Page Configuration ---
st.set_page_config(
    page_title="PQC Pro Encryptor",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={"About": f"""
        **PQC Pro Encryptor v{cfg.FORMAT_VERSION}.0**

        Uses **{cfg.KEM_ALG}** (PQC KEM) + **AES-256-GCM** (DEM) with HKDF.
        Private keys are always password protected (scrypt + AES-GCM).

        **Disclaimer:** Security relies on correct implementation, secure key management,
        and the underlying cryptographic primitives. Requires auditing for production use.
        **The developer provides no warranty.** Use at your own risk.
        """},
)

# --- Helper Functions for GUI ---


def display_pem_download(pem_string: str, filename: str, key_label: str):
    """Provides a download button for a PEM string."""
    try:
        st.download_button(
            label=f"Download {key_label} ({filename})",
            data=pem_string.encode("ascii"),  # PEM is ASCII
            file_name=filename,
            mime="application/x-pem-file",
        )
    except Exception as e:
        logger.exception(f"Error creating download button for {key_label}: {e}")
        st.error(f"Could not prepare {key_label} for download.")


def format_size(byte_count: int) -> str:
    """Format a byte count for user-facing validation messages."""
    mib = byte_count / (1024 * 1024)
    return f"{mib:.1f} MiB"


def uploaded_file_too_large(uploaded_file, max_bytes: int | None = None) -> bool:
    """Return whether a Streamlit upload exceeds the configured in-memory limit."""
    size = getattr(uploaded_file, "size", None)
    limit = cfg.MAX_FILE_BYTES if max_bytes is None else max_bytes
    return size is not None and size > limit


def uploaded_key_file_too_large(uploaded_file, max_bytes: int | None = None) -> bool:
    """Return whether a Streamlit PEM/key upload exceeds the configured limit."""
    limit = cfg.MAX_PEM_BYTES if max_bytes is None else max_bytes
    return uploaded_file_too_large(uploaded_file, limit)


def sanitize_download_filename(filename: str, fallback: str) -> str:
    """Constrain user-controlled download names to a simple local filename."""
    candidate = Path(filename or "").name.strip()
    candidate = re.sub(r"[\x00-\x1f\x7f]+", "", candidate)
    return candidate or fallback


def validate_private_key_password_for_ui(password: str) -> tuple[bool, str | None]:
    """Validate private-key password text with the core policy."""
    try:
        core.validate_private_key_password(password)
        return True, None
    except (core.PasswordRequiredError, core.WeakPasswordError) as exc:
        return False, str(exc)


# --- Main Application UI ---

try:
    active_kem_alg = core.resolve_kem_algorithm(cfg.KEM_ALG)
    kem_status_message = None
except Exception as exc:
    active_kem_alg = cfg.KEM_ALG
    kem_status_message = (
        "Post-quantum backend is not ready. Check dependency installation before generating keys or processing files."
    )
    logger.warning("Unable to resolve configured KEM algorithm: %s", exc)

st.title("🛡️ PQC Pro File Encryption / Decryption")
st.markdown(f"""
Utilizes **{active_kem_alg}** + **AES-256-GCM** hybrid encryption.
Supports password-protected private keys (PEM format).
""")

st.sidebar.header("Operations")
operation = st.sidebar.radio(
    "Choose action:",
    ["Generate Keys", "Encrypt File", "Decrypt File", "Key Utilities"],
    key="main_operation",
)

st.sidebar.markdown("---")
st.sidebar.info(f"Version: {cfg.FORMAT_VERSION}.0\nKEM: {active_kem_alg}\nDEM: AES-256-GCM")
if kem_status_message:
    st.sidebar.warning(kem_status_message)

# State Management (using session state is generally better)
if "password_gen" not in st.session_state:
    st.session_state.password_gen = ""
if "password_gen_confirm" not in st.session_state:
    st.session_state.password_gen_confirm = ""
if "password_decrypt" not in st.session_state:
    st.session_state.password_decrypt = ""

# === Key Generation ===
if operation == "Generate Keys":
    st.header("🔑 Generate PQC Key Pair")
    st.markdown(f"Generates a **{active_kem_alg}** public/private key pair (PEM format).")
    st.info(f"Using KEM Algorithm: **{active_kem_alg}**")

    st.subheader("Private Key Password")
    password_valid = False
    st.session_state.password_gen = st.text_input("Enter Password:", type="password", key="gen_pw1")
    st.session_state.password_gen_confirm = st.text_input("Confirm Password:", type="password", key="gen_pw2")
    if st.session_state.password_gen or st.session_state.password_gen_confirm:
        if not st.session_state.password_gen:
            st.warning("Password cannot be empty.")
        elif st.session_state.password_gen != st.session_state.password_gen_confirm:
            st.warning("Passwords do not match.")
        else:
            password_valid, password_error = validate_private_key_password_for_ui(st.session_state.password_gen)
            if password_valid:
                st.success("Passwords match.")
            else:
                st.warning(password_error)
    else:
        st.warning("A password is required. Unencrypted private keys are not supported.")
    disable_gen_button = not password_valid

    st.markdown("---")
    if st.button(
        f"Generate {active_kem_alg} Key Pair",
        key="gen_button",
        disabled=disable_gen_button or bool(kem_status_message),
    ):
        final_password = st.session_state.password_gen if password_valid else None

        with st.status(f"Generating {active_kem_alg} keys...", expanded=True) as status:
            st.write("Generating raw OQS key pair...")
            raw_pub_key, raw_priv_key = core.generate_oqs_keys(active_kem_alg)

            if raw_pub_key and raw_priv_key:
                st.write("Raw keys generated.")
                st.write("Formatting Public Key (PEM)...")
                pub_pem = core.save_key_pem(raw_pub_key, active_kem_alg, "public")

                st.write("Formatting Private Key (PEM)...")
                st.write("(Encrypting private key with password...)")
                priv_pem = core.save_key_pem(raw_priv_key, active_kem_alg, "private", password=final_password)

                # Cleanup raw keys immediately after PEM generation
                del raw_pub_key
                del raw_priv_key

                if pub_pem and priv_pem:
                    status.update(label="Key generation complete!", state="complete")
                    st.success("Key pair generated successfully!")
                    st.markdown("---")
                    st.subheader("Download Your Keys (PEM Format)")
                    st.warning(
                        "🚨 **CRITICAL:** Securely store the **Private Key** file. "
                        "Remember the password. Loss = permanent data loss."
                    )

                    pub_filename = f"{active_kem_alg.lower()}_public.pem"
                    priv_filename = f"{active_kem_alg.lower()}_private.pem"

                    col1, col2 = st.columns(2)
                    with col1:
                        display_pem_download(pub_pem, pub_filename, "Public Key")
                    with col2:
                        display_pem_download(priv_pem, priv_filename, "Private Key")

                    st.markdown("---")
                    st.info("Share the Public Key (`.pem`) file with others to allow them to encrypt files for you.")

                else:
                    err_msg = "Failed to format keys into PEM format."
                    logger.error(err_msg)
                    status.update(label=err_msg, state="error")
                    st.error(err_msg)
            else:
                err_msg = f"Failed to generate raw keys for {active_kem_alg}."
                logger.error(err_msg)
                status.update(label=err_msg, state="error")
                st.error(err_msg + " Check logs for details. Is liboqs working?")

# === Encryption ===
elif operation == "Encrypt File":
    st.header("⬆️ Encrypt a File")
    st.markdown("Encrypt using the recipient's **Public Key** (PEM format).")

    uploaded_file = st.file_uploader("1. Choose File to Encrypt", type=None, key="enc_file_input")
    public_key_pem_file = st.file_uploader(
        "2. Upload Recipient's Public Key (.pem)", type=["pem"], key="enc_pubkey_input"
    )

    if uploaded_file and public_key_pem_file:
        st.markdown("---")
        input_too_large = uploaded_file_too_large(uploaded_file)
        if input_too_large:
            st.error(
                f"Selected file is {format_size(uploaded_file.size)}. "
                f"The maximum supported size is {format_size(cfg.MAX_FILE_BYTES)}."
            )
        if uploaded_key_file_too_large(public_key_pem_file):
            st.error(
                f"Public key file is {format_size(public_key_pem_file.size)}. "
                f"The maximum supported PEM size is {format_size(cfg.MAX_PEM_BYTES)}."
            )
            st.stop()
        pub_pem_content: str | None
        try:
            pub_pem_content = public_key_pem_file.getvalue().decode("utf-8")
        except Exception as e:
            logger.exception("Error reading public key file: %s", e)
            st.error("Could not read the public key file.")
            pub_pem_content = None  # Halt further processing

        if pub_pem_content:
            # Load public key (password ignored by load_key_pem for public keys)
            pub_key_bytes, kem_alg_from_key, key_type = core.load_key_pem(pub_pem_content)

            if pub_key_bytes and kem_alg_from_key is not None and key_type == "public":
                st.success(f"Public Key loaded successfully (Algorithm: {kem_alg_from_key}).")

                original_filename = Path(uploaded_file.name)
                suggested_output_filename = f"{original_filename.stem}_encrypted.pqc"
                output_filename = st.text_input(
                    "3. Encrypted file name:",
                    value=suggested_output_filename,
                    key="enc_output_name",
                )
                output_filename = sanitize_download_filename(output_filename, suggested_output_filename)

                if not output_filename:
                    st.warning("Please provide a name for the encrypted file.")
                elif st.button("Encrypt File", key="enc_button", disabled=input_too_large):
                    input_data = uploaded_file.getvalue()
                    if len(input_data) == 0:
                        st.warning(
                            "Input file is empty. Encryption will proceed, resulting file will contain "
                            "header and metadata only."
                        )
                    elif len(input_data) > cfg.MAX_FILE_BYTES:
                        st.error("Selected file exceeds the maximum supported size.")
                        st.stop()

                    with st.status(f"Encrypting '{uploaded_file.name}'...", expanded=False) as status:
                        try:
                            status.write("Reading input file...")  # Already done by getvalue()
                            status.write(f"Performing {kem_alg_from_key} + AES-GCM encryption...")
                            encrypted_blob = core.encrypt_file_pro(input_data, pub_key_bytes, kem_alg_from_key)
                            status.write("Cleaning up...")
                            del input_data
                            del pub_key_bytes

                            if encrypted_blob:
                                status.update(label="Encryption successful!", state="complete")
                                st.success("File encrypted successfully!")
                                st.download_button(
                                    label=f"Download Encrypted File ({output_filename})",
                                    data=encrypted_blob,
                                    file_name=output_filename,
                                    mime="application/octet-stream",
                                    key="enc_download_button",
                                )
                            else:
                                err_msg = "Encryption process failed."
                                logger.error(err_msg + " (Core function returned None)")
                                status.update(label=err_msg, state="error")
                                st.error(err_msg + " Check logs.")

                        except Exception as e:
                            logger.exception(f"Unhandled exception during encryption action: {e}")
                            status.update(label="Encryption Error", state="error")
                            st.error("An unexpected error occurred during encryption. Check server logs for details.")

            elif key_type == "private":
                st.error("Error: The uploaded key file appears to be a Private Key, not a Public Key.")
            else:
                st.error(
                    "Failed to load or validate the Public Key from the provided PEM file. Is it correctly formatted?"
                )


# === Decryption ===
elif operation == "Decrypt File":
    st.header("⬇️ Decrypt a File")
    st.markdown("Decrypt a `.pqc` file using **your** corresponding **Private Key** (PEM format).")

    encrypted_file = st.file_uploader("1. Choose Encrypted File (.pqc)", type=["pqc"], key="dec_file_input")
    private_key_pem_file = st.file_uploader("2. Upload Your Private Key (.pem)", type=["pem"], key="dec_privkey_input")

    if encrypted_file and private_key_pem_file:
        st.markdown("---")
        encrypted_too_large = uploaded_file_too_large(encrypted_file, cfg.MAX_ENCRYPTED_FILE_BYTES)
        if encrypted_too_large:
            st.error(
                f"Selected encrypted file is {format_size(encrypted_file.size)}. "
                f"The maximum supported encrypted file size is {format_size(cfg.MAX_ENCRYPTED_FILE_BYTES)}."
            )
        if uploaded_key_file_too_large(private_key_pem_file):
            st.error(
                f"Private key file is {format_size(private_key_pem_file.size)}. "
                f"The maximum supported PEM size is {format_size(cfg.MAX_PEM_BYTES)}."
            )
            st.stop()
        # First, inspect the private key security metadata.
        priv_pem_content: str | None
        try:
            priv_pem_content = private_key_pem_file.getvalue().decode("utf-8")
            priv_info = core.inspect_key_pem_strict(priv_pem_content)
            priv_type = str(priv_info.get("key_type", "")).title()
        except Exception as e:
            logger.exception("Error reading private key file: %s", e)
            st.error("Could not read a supported encrypted private key file.")
            priv_pem_content = None  # Halt

        password_provided = False
        if priv_pem_content:
            if priv_type == "Private":
                st.subheader("Password Required for Private Key")
                st.session_state.password_decrypt = st.text_input(
                    "Enter Private Key Password:", type="password", key="dec_pw"
                )
                if st.session_state.password_decrypt:
                    password_provided = True
                else:
                    st.warning("This private key is encrypted. Please enter the password.")
            elif priv_type == "Public":
                st.error(
                    "Error: The uploaded key file appears to be a Public Key. A Private Key is required for decryption."
                )
                priv_pem_content = None  # Halt
            elif not priv_type:
                st.error("Could not determine key type or algorithm from the Private Key file. Is it a valid PEM?")
                priv_pem_content = None  # Halt

        if priv_pem_content and password_provided:
            original_filename = Path(encrypted_file.name)
            suggested_output_filename = guess_decrypted_filename(original_filename)
            output_filename = st.text_input(
                "3. Decrypted file name:",
                value=suggested_output_filename,
                key="dec_output_name",
            )
            output_filename = sanitize_download_filename(output_filename, suggested_output_filename)

            disable_dec_button = not output_filename or not password_provided or encrypted_too_large

            if st.button("Decrypt File", key="dec_button", disabled=disable_dec_button):
                encrypted_blob = encrypted_file.getvalue()
                if len(encrypted_blob) == 0:
                    st.error("Encrypted file appears to be empty. Cannot decrypt.")
                else:
                    if len(encrypted_blob) > cfg.MAX_ENCRYPTED_FILE_BYTES:
                        st.error("Selected encrypted file exceeds the maximum supported encrypted file size.")
                        st.stop()

                    with st.status(f"Decrypting '{encrypted_file.name}'...", expanded=False) as status:
                        try:
                            status.write("Loading private key...")
                            priv_key_bytes, kem_alg_key, key_type = core.load_key_pem(
                                priv_pem_content,
                                password=st.session_state.password_decrypt,
                            )

                            if not priv_key_bytes or key_type != "private":
                                err_msg = "Failed to load private key."
                                err_msg += " Check if password is correct."
                                logger.error(err_msg + " (Core function returned None or wrong key type)")
                                status.update(label=err_msg, state="error")
                                st.error(err_msg)
                            else:
                                status.write(f"Private key loaded (Algorithm: {kem_alg_key}).")
                                status.write("Reading encrypted data...")  # Already done by getvalue()
                                status.write("Performing decryption and authentication...")

                                decrypted_data, _detected_alg = core.decrypt_file_pro(
                                    encrypted_blob,
                                    priv_key_bytes,
                                    expected_kem_alg=kem_alg_key,
                                )

                                status.write("Cleaning up...")
                                del encrypted_blob
                                del priv_key_bytes  # Very important!

                                if decrypted_data is not None:
                                    status.update(label="Decryption successful!", state="complete")
                                    st.success("File decrypted successfully!")

                                    # Guess mime type for download
                                    mime_type, _ = mimetypes.guess_type(output_filename)
                                    mime_type = mime_type or "application/octet-stream"  # Default

                                    st.download_button(
                                        label=f"Download Decrypted File ({output_filename})",
                                        data=decrypted_data,
                                        file_name=output_filename,
                                        mime=mime_type,
                                        key="dec_download_button",
                                    )
                                    # Clean up decrypted data after download button is prepared
                                    del decrypted_data
                                else:
                                    err_msg = "Decryption failed."
                                    logger.error(
                                        err_msg + " (Core function returned None - check for auth errors in logs)"
                                    )
                                    status.update(label=err_msg, state="error")
                                    st.error(
                                        err_msg + " Possible reasons: incorrect private key, wrong password, "
                                        "file corrupted/tampered with."
                                    )

                        except Exception as e:
                            logger.exception(f"Unhandled exception during decryption action: {e}")
                            status.update(label="Decryption Error", state="error")
                            st.error("An unexpected error occurred during decryption. Check server logs for details.")


# === Key Utilities ===
elif operation == "Key Utilities":
    st.header("🛠️ Key Utilities")
    st.markdown("Inspect a PEM key file.")

    key_util_file = st.file_uploader("Upload Key File (.pem)", type=["pem"], key="util_key_input")

    if key_util_file:
        if uploaded_key_file_too_large(key_util_file):
            st.error(
                f"Key file is {format_size(key_util_file.size)}. "
                f"The maximum supported PEM size is {format_size(cfg.MAX_PEM_BYTES)}."
            )
            st.stop()
        try:
            pem_content = key_util_file.getvalue().decode("utf-8")
            algo, key_type, is_encrypted = core.get_key_info_pem(pem_content)

            if algo and key_type:
                st.success("Key file parsed successfully.")
                st.markdown("---")
                st.write(f"**Key Type:** `{key_type}`")
                st.write(f"**Algorithm:** `{algo}`")
                if key_type == "Private":
                    st.write(f"**Password Encrypted:** `{'Yes' if is_encrypted else 'No'}`")
                st.markdown("---")
                st.info("Note: This only checks the headers and format, not the validity of the key data itself.")
            else:
                st.error("Failed to parse key file. Is it a valid PEM format with expected headers?")

        except Exception as e:
            logger.exception(f"Error inspecting key file: {e}")
            st.error("Could not read or parse the key file.")
