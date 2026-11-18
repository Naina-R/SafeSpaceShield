
import streamlit as st

from analyzer import (
    detect_suspicious_keywords,
    detect_suspicious_url_patterns,
    detect_ip_based_urls,
    calculate_risk,
    generate_explanation
)

# Sample messages for demonstration
SAMPLE_MESSAGES = {
    "🔴 High Risk – Bank phishing": (
        "URGENT! Your bank account has been blocked. "
        "Verify your account immediately at "
        "http://bank-verify.com/login. "
        "Enter your password and OTP now!"
    ),

    "🟠 Medium Risk – Delivery message": (
        "Your delivery is pending. "
        "Please check the delivery update at "
        "http://delivery-update.com/pay"
    ),

    "🟢 Low Risk – Harmless message": (
        "Good morning! Our computer science department "
        "has scheduled a programming workshop for Friday "
        "at 10 AM in Lab 2. Please bring your laptop."
    )
}

# Function to load a selected sample message
def load_sample_message():
    selected_sample = st.session_state["sample_choice"]

    if selected_sample in SAMPLE_MESSAGES:
        st.session_state["message_input"] = SAMPLE_MESSAGES[selected_sample]


# Page configuration
st.set_page_config(
    page_title="SafeSpace Shield",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Sidebar
with st.sidebar:
    st.title("🛡️ SafeSpace Shield")

    st.divider()

    dark_mode = st.toggle(
        "🌙 Dark Mode",
        value=False,
        key="dark_mode"
    )

    st.markdown("### About")

    st.write(
        "An intelligent cybersecurity awareness tool "
        "that helps identify potential phishing and scam messages."
    )

    st.divider()

    st.markdown("### Features")

    st.markdown(
        """
        - Suspicious keyword detection
        - URL pattern detection
        - IP-based URL detection
        - Risk scoring
        - Safety recommendations
        """
    )

    st.divider()

    st.caption("Think Before You Click.")


# Theme styling
if dark_mode:
    st.markdown(
        """
        <style>
        .stApp,
        [data-testid="stAppViewContainer"] {
            background-color: #0B1220;
            color: #E5E7EB;
        }

        [data-testid="stHeader"] {
            background-color: #0B1220;
        }

        [data-testid="stSidebar"] {
            background-color: #111C30;
        }

        [data-testid="stSidebar"] * {
            color: #E5E7EB;
        }

        [data-testid="stMarkdownContainer"] p,
        [data-testid="stMarkdownContainer"] li,
        [data-testid="stMarkdownContainer"] h1,
        [data-testid="stMarkdownContainer"] h2,
        [data-testid="stMarkdownContainer"] h3 {
            color: #E5E7EB;
        }

        [data-testid="stTextArea"] textarea {
            background-color: #172338;
            color: #FFFFFF;
            border: 1px solid #40516B;
        }

        [data-testid="stTextArea"] textarea::placeholder {
            color: #AAB7C8;
        }

        [data-testid="stVerticalBlockBorderWrapper"] {
            background-color: #142137;
            border-color: #263750;
            border-radius: 12px;
        }

        /* Clear Message button */
        .stButton button {
            background-color: transparent;
            color: #60A5FA;
            border: 1px solid #40516B;
            border-radius: 8px;
            transition: all 0.2s ease;
    }

        /* Clear Message hover effect */
        .stButton button:hover {
            background-color: #1E3A5F;
            color: #FFFFFF;
            border-color: #60A5FA;
    }

        /* Analyze Message button */
        [data-testid="stFormSubmitButton"] button {
            background-color: #2563EB;
            color: #FFFFFF;
            border: 1px solid #2563EB;
            border-radius: 8px;
            font-weight: 600;
            transition: all 0.2s ease;
}

        /* Analyze Message hover effect */
        [data-testid="stFormSubmitButton"] button:hover {
            background-color: #1D4ED8;
            border-color: #1D4ED8;
            color: #FFFFFF;
}
        </style>
        """,
        unsafe_allow_html=True
    )

else:
    st.markdown(
        """
        <style>
        .stApp,
        [data-testid="stAppViewContainer"] {
            background-color: #F5F8FC;
            color: #1F2937;
        }

        [data-testid="stHeader"] {
            background-color: #F5F8FC;
        }

        [data-testid="stSidebar"] {
            background-color: #EAF0F8;
        }

        [data-testid="stSidebar"] * {
            color: #1F2937;
        }

        [data-testid="stMarkdownContainer"] p,
        [data-testid="stMarkdownContainer"] li,
        [data-testid="stMarkdownContainer"] h1,
        [data-testid="stMarkdownContainer"] h2,
        [data-testid="stMarkdownContainer"] h3 {
            color: #1F2937;
        }

        [data-testid="stTextArea"] textarea {
            background-color: #FFFFFF;
            color: #1F2937;
            border: 1px solid #CBD5E1;
        }

        [data-testid="stTextArea"] textarea::placeholder {
            color: #64748B;
        }

        [data-testid="stVerticalBlockBorderWrapper"] {
            background-color: #FFFFFF;
            border-color: #D8E1EC;
            border-radius: 12px;
        }

        
        /* Clear Message button */
        .stButton button {
            background-color: #FFFFFF !important;
            color: #1D4ED8 !important;
            border: 1px solid #94A3B8 !important;
            border-radius: 8px;
            font-weight: 600;
            transition: all 0.2s ease;
        }

        /* Clear Message hover */
        .stButton button:hover {
            background-color: #DBEAFE !important;
            color: #1D4ED8 !important;
            border-color: #2563EB !important;
        }

        /* Analyze Message button */
        [data-testid="stFormSubmitButton"] button {
            background-color: #2563EB !important;
            color: #FFFFFF !important;
            border: 1px solid #2563EB !important;
            border-radius: 8px;
            font-weight: 600;
        }

        /* Analyze Message hover */
        [data-testid="stFormSubmitButton"] button:hover {
            background-color: #1D4ED8 !important;
            color: #FFFFFF !important;
            border-color: #1D4ED8 !important;
        }

        /* Sidebar text */
        [data-testid="stSidebar"] {
            color: #1F2937 !important;
        }

        [data-testid="stSidebar"] [data-testid="stMarkdownContainer"],
        [data-testid="stSidebar"] [data-testid="stWidgetLabel"],
        [data-testid="stSidebar"] [data-testid="stCaptionContainer"] {
            color: #1F2937 !important;
        }

        /* Sidebar expand and collapse controls */
        [data-testid="stHeader"] button,
        [data-testid="stSidebar"] button {
            color: #1F2937 !important;
        }


        /* Force Analyze button text to white */
        [data-testid="stFormSubmitButton"] button,
        [data-testid="stFormSubmitButton"] button *,
        [data-testid="stFormSubmitButton"] button p {
            color: #FFFFFF !important;
        }

        /* Make sidebar controls visible */
        [data-testid="stSidebarCollapsedControl"] button,
        [data-testid="stSidebarCollapseButton"] button,
       

        /* Make sidebar control icons visible */
        [data-testid="stSidebarCollapsedControl"] svg,
        [data-testid="stSidebarCollapseButton"] svg,
        
        }

        /* Dark Mode toggle label */
        [data-testid="stToggle"] label,
        [data-testid="stToggle"] label *,
        [data-testid="stSidebar"] label {
            color: #1F2937 !important;
        }

        /* Dark Mode toggle switch */
        [data-testid="stToggle"] [role="switch"] {
            background-color: #CBD5E1 !important;
            border: 1px solid #64748B !important;
        }

        /* Dark Mode toggle switch when enabled */
        [data-testid="stToggle"] [role="switch"][aria-checked="true"] {
            background-color: #2563EB !important;
            border-color: #2563EB !important;
        }

        /* Toggle keyboard focus */
        [data-testid="stToggle"] [role="switch"]:focus-visible {
            outline: 2px solid #2563EB !important;
            outline-offset: 3px;
        }

        /* Make the Dark Mode toggle track visible */
        [data-testid="stToggle"] [role="switch"] {
            background-color: #64748B !important;
            border: 2px solid #475569 !important;
            opacity: 1 !important;
        }

        /* Dark Mode toggle ON */
        [data-testid="stToggle"] [role="switch"][aria-checked="true"] {
            background-color: #2563EB !important;
            border-color: #1D4ED8 !important;
        }

        /* Sidebar collapse control */
        [data-testid="stSidebarCollapseButton"] {
            background-color: #DBEAFE !important;
            color: #1D4ED8 !important;
            opacity: 1 !important;
        }

        /* Sidebar expand control */
        [data-testid="stSidebarCollapsedControl"] {
            background-color: #DBEAFE !important;
            color: #1D4ED8 !important;
            opacity: 1 !important;
        }

        /* Sidebar control icons */
        [data-testid="stSidebarCollapseButton"] svg,
        [data-testid="stSidebarCollapsedControl"] svg {
            color: #1D4ED8 !important;
            stroke: #1D4ED8 !important;
            opacity: 1 !important;
        }

        
        </style>
        """,
        unsafe_allow_html=True
    )


# Function to clear the message

def clear_message():
    st.session_state["message_input"] = ""
    st.session_state["sample_choice"] = "Choose a sample..."


# Application heading
st.title("🛡️ SafeSpace Shield")

st.markdown(
    "### Think Before You Click. Understand Before You Trust."
)

st.markdown(
    """
    Your personal online safety companion.

    Analyze suspicious SMS messages, emails, and links.
    Understand potential threats and learn how to protect yourself.
    """
)

st.divider()


# Message input section
with st.container(border=True):

    st.header("🔍 Analyze a Message")

    st.write(
        "Paste the message you want to check. "
        "SafeSpace Shield will analyze it for potential warning signs."
    )

    # Sample message selector
    st.selectbox(
        "Try a sample message",
        options=[
            "Choose a sample...",
            "🔴 High Risk – Bank phishing",
            "🟠 Medium Risk – Delivery message",
            "🟢 Low Risk – Harmless message"
        ],
        key="sample_choice",
        on_change=load_sample_message,
        help="Choose a sample message to see how SafeSpace Shield analyzes different risk levels."
    )

    st.caption(
    "Select a sample message above, or enter your own message below."
    )
    
    # Message analysis form
    with st.form(key="analysis_form"):

        message = st.text_area(
            "Your message",
            placeholder=(
                "Example: Your bank account is blocked! "
                "Verify your account immediately..."
            ),
            height=180,
            max_chars=5000,
            key="message_input"
        )

        analyze_clicked = st.form_submit_button(
            "🔍 Analyze Message",
            use_container_width=True,
            type="primary"
        )

    # Clear message button
    st.button(
        "🗑️ Clear Message",
        on_click=clear_message
    )

    st.caption(
        "Your message is analyzed locally by the application. "
        "Avoid entering real passwords, OTPs, or other sensitive information."
    )




# Analysis button
if analyze_clicked:

    if message.strip():

        # Run detection engine
        keyword_results = detect_suspicious_keywords(message)
        url_results = detect_suspicious_url_patterns(message)
        ip_results = detect_ip_based_urls(message)
        risk_results = calculate_risk(message)
        explanation_results = generate_explanation(message)

        # Analysis report
        st.divider()
        st.header("📋 Analysis Report")

        # Risk classification
        risk_level = risk_results["risk_level"]
        risk_score = risk_results["score"]

        with st.container(border=True):

            st.subheader("🚦 Security Assessment")

            if risk_level == "High":
                st.error(
                    "🚨 HIGH RISK — Multiple suspicious indicators detected."
                )

            elif risk_level == "Medium":
                st.warning(
                    "⚠️ MEDIUM RISK — Some suspicious indicators detected."
                )

            else:
                st.info(
                    "ℹ️ LOW RISK — No major indicators detected by current rules."
                )

            st.metric("Overall Risk Score", risk_score)

        # Detection metrics
        with st.container(border=True):

            st.subheader("📊 Detection Summary")

            col1, col2, col3 = st.columns(3)

            col1.metric("Suspicious Keywords", len(keyword_results))
            col2.metric("URL Patterns", len(url_results))
            col3.metric("IP-Based URLs", len(ip_results))

        # Suspicious keywords
        st.subheader("🔎 Detected Suspicious Keywords")

        if keyword_results:
            st.warning(" • ".join(keyword_results))
        else:
            st.success("No suspicious keywords detected.")

        # URL security analysis
        st.subheader("🔗 URL Security Analysis")

        if url_results:
            st.markdown("**Suspicious URL patterns detected:**")
            st.warning(" • ".join(url_results))
        else:
            st.success("No suspicious URL patterns detected.")

        if ip_results:
            st.markdown("**IP-Based URLs detected:**")

            for ip_url in ip_results:
                st.warning(ip_url)
        else:
            st.info("No IP-based URLs detected.")

        # Explanations and recommendations
        col1, col2 = st.columns(2)

        with col1:
            with st.container(border=True):
                st.subheader("🧠 Why Was It Flagged?")

                for reason in explanation_results["reasons"]:
                    st.markdown(f"- {reason}")

        with col2:
            with st.container(border=True):
                st.subheader("🛡️ Safety Recommendations")

                for recommendation in explanation_results["recommendations"]:
                    st.markdown(f"- {recommendation}")

        st.divider()

        st.caption(
            "SafeSpace Shield provides an initial automated assessment. "
            "A low-risk result does not guarantee that a message is safe. "
            "Always verify important requests through official channels."
        )

    else:
        st.warning("Please enter a message before analyzing.")

# Footer
st.divider()

st.caption("SafeSpace Shield | Your Online Safety Companion")
