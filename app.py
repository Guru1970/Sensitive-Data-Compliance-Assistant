import streamlit as st
import pandas as pd
from pypdf import PdfReader
import os
import spacy
import re
from PIL import Image
import pytesseract
from pdf2image import convert_from_bytes

# Set page layout
st.set_page_config(page_title="Compliance Assistant", layout="wide")

st.title("🛡️ Sensitive Data & Compliance Assistant")
st.write("Upload a document to scan for sensitive data (PII) and assess compliance risks.")

# 1. File Uploader (Expanded types to include standard image files)
uploaded_file = st.file_uploader("Upload a document (PDF, TXT, CSV, PNG, JPG)", type=["pdf", "txt", "csv", "png", "jpg", "jpeg"])

# 2. Text Extraction Logic (Enhanced with OCR capabilities)
if uploaded_file is not None:
    file_extension = uploaded_file.name.split('.')[-1].lower()
    extracted_text = ""

    with st.spinner("Processing file and extracting content..."):
        if file_extension == "pdf":
            # First, try standard digital extraction
            reader = PdfReader(uploaded_file)
            for page in reader.pages:
                text_content = page.extract_text()
                if text_content:
                    extracted_text += text_content + "\n"
            
            # 🔥 FALLBACK OCR: If standard reader extracted nothing, it's a scanned PDF image
            if not extracted_text.strip():
                st.info("ℹ️ Scanned PDF detected. Initiating optical layout OCR processing...")
                # Reset file pointer and convert pages to image bytes
                uploaded_file.seek(0)
                images = convert_from_bytes(uploaded_file.read())
                for i, image in enumerate(images):
                    extracted_text += pytesseract.image_to_string(image) + "\n"
                
        elif file_extension in ["png", "jpg", "jpeg"]:
            # 🔥 DIRECT IMAGE OCR PROCESSING
            image = Image.open(uploaded_file)
            extracted_text = pytesseract.image_to_string(image)

        elif file_extension == "csv":
            df = pd.read_csv(uploaded_file, encoding='Latin1')
            extracted_text = df.to_string()
          
        elif file_extension == "txt":
            extracted_text = uploaded_file.getvalue().decode("utf-8")

    st.success("File uploaded and read successfully!")
    
    # Let's prove it works by displaying the extracted text
    with st.expander("👀 Preview Extracted Text"):
        if file_extension=="csv":
            st.dataframe(df)
        else:
            st.text(extracted_text)
    if extracted_text:
        
        # =========================================================================
        # 🔑 MAIN API KEY CONFIGURATION (Initializes BEFORE UI Columns)
        # =========================================================================
        st.divider()
        api_key = st.text_input("Enter your Google AI Studio Key to activate Dashboard & Chat:", type="password")
        
        if api_key:
            
                import google.generativeai as genai
                genai.configure(api_key=api_key)
                
                # 🔍 SAFE API MODEL SCANNER
                with st.spinner("Syncing available models..."):
                    try:
                        available_models = []
                        for m in genai.list_models():
                            methods = getattr(m, 'supported_generation_methods', getattr(m, 'supported_actions', []))
                            if any('generateContent' in method for method in methods):
                                available_models.append(m.name)
                    except Exception:
                        available_models = []
                
                chosen_model = available_models[0] if available_models else "gemini-pro"
                
                # Instantiate model in global scope so BOTH columns can reach it
                model = genai.GenerativeModel(chosen_model)
        # 📊 CREATE THE MAIN TWO-COLUMN SPLIT-SCREEN DASHBOARD
                col_left, col_right = st.columns([1.2, 0.8])
                with col_left:
                    
                # --- SENSITIVE DATA IDENTIFICATION (FULLY EXPANDED) ---
                    st.subheader("🔍 Sensitive Data Scanner")
                    
                    # 📌 1. Define Core Regular Expressions
                    pan_pattern = r"[A-Z]{5}[0-9]{4}[A-Z]{1}"
                    aadhaar_pattern = r"\b\d{4}\s?\d{4}\s?\d{4}\b"
                    email_pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
                    phone_pattern = r"(?:\+91|0)?[6-9]\d{9}\b"
                    credit_card_pattern = r"\b\d{4}[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}\b"
                    ifsc_pattern = r"\b[A-Z]{4}0[A-Z0-9]{6}\b"
                    api_key_pattern = r"\b(?:sk|api|key|secret)-[a-zA-Z0-9]{24,}\b"
                    emp_id_pattern = r"\bEMP[-\s]?\d{3,6}\b"
                    confidential_pattern = r"(?i)\b(strictly confidential|proprietary information|internal use only|trade secret)\b"

                    # 📌 2. Execute Pattern Matches
                    found_pans = set(re.findall(pan_pattern, extracted_text))
                    found_aadhaars = set(re.findall(aadhaar_pattern, extracted_text))
                    found_emails = set(re.findall(email_pattern, extracted_text))
                    found_phones = set(re.findall(phone_pattern, extracted_text))
                    found_cards = set(re.findall(credit_card_pattern, extracted_text))
                    found_ifscs = set(re.findall(ifsc_pattern, extracted_text))
                    found_api_keys = set(re.findall(api_key_pattern, extracted_text))
                    found_emp_ids = set(re.findall(emp_id_pattern, extracted_text))
                    found_confidential = set(re.findall(confidential_pattern, extracted_text))

                    # 📌 3. Statistical NLP tracking with spaCy (For Names and Orgs)
                    import spacy
                    nlp = spacy.load("en_core_web_sm")
                    doc = nlp(extracted_text)
                    
                    blacklist = ["Aadhar", "Aadhaar", "PAN", "Number", "Employee", "Name", "IFSC", "CONFIDENTIAL"]
                    found_names = set([
                        ent.text for ent in doc.ents 
                        if ent.label_ == "PERSON" and not any(bad_word in ent.text for bad_word in blacklist)
                    ])
                    found_orgs = set([ent.text for ent in doc.ents if ent.label_ == "ORG"])

                    # 📌 4. Render Dashboard Analytics Metrics
                    st.markdown("### 📌 Pattern Matches (Regex)")
                    st.write(f"**PAN Cards:** {len(found_pans)} | **Aadhaar:** {len(found_aadhaars)} | **Emails:** {len(found_emails)}")
                    st.write(f"**Phone Numbers:** {len(found_phones)} | **Credit Cards:** {len(found_cards)}")
                    st.write(f"**Bank IFSCs:** {len(found_ifscs)} | **Employee IDs:** {len(found_emp_ids)}")
                    st.write(f"**Exposed Credentials:** {len(found_api_keys)} | **Confidential Markers:** {len(found_confidential)}")
                        
                        # Expandable list detail view
                    with st.expander("🔍 View Detailed Matches"):
                            # Existing checks
                            if found_pans: st.json({"PAN Cards": list(found_pans)})
                            if found_aadhaars: st.json({"Aadhaar Numbers": list(found_aadhaars)})
                            if found_emails: st.json({"Emails": list(found_emails)})
                            if found_phones: st.json({"Phones": list(found_phones)})
                            if found_cards: st.json({"Cards": list(found_cards)})
                            if found_ifscs: st.json({"IFSC Codes": list(found_ifscs)})
                            if found_api_keys: st.json({"API Secrets": list(found_api_keys)})
                            if found_emp_ids: st.json({"Employee IDs": list(found_emp_ids)})

                    st.markdown("#### 🧠 Context Matches (NLP)")
                        
                    # 📦 Combine data into a clean dropdown selector
                    nlp_options = ["— Select Category —"]
                    if found_names: nlp_options.append(f"👤 Detected Names ({len(found_names)})")
                    if found_orgs: nlp_options.append(f"🏢 Organizations ({len(found_orgs)})")
                        
                        # Render the drop-down menu
                    selected_nlp = st.selectbox("Filter entity extraction results:", nlp_options)
                        
                        # Dynamically display data based on what the user selects
                    if "Detected Names" in selected_nlp:
                        st.markdown("**Identified Individuals:**")
                        for name in found_names:
                            st.write(f"• {name}")
                                
                    elif "Organizations" in selected_nlp:
                        st.markdown("**Identified Entities / Corporations:**")
                        for org in found_orgs:
                            # Clean up ugly raw newline escape tags like \r\n from data view if present
                            clean_org = org.replace("\r", "").replace("\n", "").strip()
                            st.write(f"• {clean_org}")
                                
                    else:
                        st.caption("Select an option above to inspect identified contextual entities.")

                    # --- PRIVACY REDACTION ENGINE UPDATE ---
                    # --- PRIVACY REDACTION PREVIEW (UI ENHANCED) ---
                    st.divider()
                    
                    # Wrap the entire preview engine inside a clean, collapsed expander
                    with st.expander("🛡️ View Redacted Document Preview", expanded=False):
                        st.markdown("*Review the securely masked compliance output below before sharing or exporting:*")
                        
                        redacted_text = extracted_text
                        for pan in found_pans: redacted_text = redacted_text.replace(pan, "██████████")
                        for aadhaar in found_aadhaars: redacted_text = redacted_text.replace(aadhaar, "████-████-████")
                        for email in found_emails: redacted_text = redacted_text.replace(email, "[REDACTED EMAIL]")
                        for phone in found_phones: redacted_text = redacted_text.replace(phone, "[REDACTED PHONE]")
                        for card in found_cards: redacted_text = redacted_text.replace(card, "████-████-████-████")
                        for ifsc in found_ifscs: redacted_text = redacted_text.replace(ifsc, "[REDACTED IFSC]")
                        for api_key in found_api_keys: redacted_text = redacted_text.replace(api_key, "[REDACTED CREDENTIAL]")
                        for emp_id in found_emp_ids: redacted_text = redacted_text.replace(emp_id, "[REDACTED EMP ID]")
                        for item in found_confidential: redacted_text = redacted_text.replace(item, "[CLASSIFIED DATA]")
                        for name in found_names: redacted_text = redacted_text.replace(name, "[REDACTED NAME]")
                            
                        # 'height=250' prevents any document from growing vertically beyond this compact tray
                        st.text_area(
                            label="Anonymized Compliance Output View:", 
                            value=redacted_text, 
                            height=250,
                            disabled=True # Keeps it secure and read-only for presentation
                        )
                        # Let users export the safe document
                        st.download_button(
                            label="📥 Download Redacted Document",
                            data=redacted_text,
                            file_name=f"redacted_{uploaded_file.name.split('.')[0]}.txt",
                            mime="text/plain",
                            use_container_width=True
                        )
                    
                    
                # --- RISK CLASSIFICATION ENGINE ---
                    st.divider()
                    st.subheader("⚠️ Document Risk Assessment")

                    # 1. Determine baseline flags and counts
                    total_identity_tokens = len(found_pans) + len(found_aadhaars)
                    has_critical_financials = len(found_cards) > 0 or len(found_api_keys) > 0
                    has_medium_identifiers = len(found_ifscs) > 0 or len(found_emp_ids) > 0 or total_identity_tokens > 0

                    # 2. Risk Evaluation Logic
                    if has_critical_financials or total_identity_tokens > 2:
                        risk_level = "High Risk"
                        risk_color = "red"
                        risk_desc = "🔴 CRITICAL EXPOSURE: This document contains high-entropy access credentials, active financial instruments, or multiple national identity tokens. Access must be tightly restricted."
                    elif has_medium_identifiers or len(found_confidential) > 0:
                        risk_level = "Medium Risk"
                        risk_color = "orange"
                        risk_desc = "🟡 MODERATE EXPOSURE: This document contains corporate infrastructure tokens (Employee IDs, Bank Routing Codes, or unique Identity keys). Requires monitored authorization."
                    else:
                        risk_level = "Low Risk"
                        risk_color = "green"
                        risk_desc = "🟢 MINIMAL EXPOSURE: This document contains basic public communication keys (Emails, Phone Numbers) or generic text string variables. Safe for general internal workflows."

                    # 3. Render Metric Dashboard UI
                    st.markdown(f"### Assessment Verdict: :{risk_color}[**{risk_level}**]")
                    
                    # Styled warning alert box based on tier
                    if risk_level == "High Risk":
                        st.error(risk_desc)
                    elif risk_level == "Medium Risk":
                        st.warning(risk_desc)
                    else:
                        st.success(risk_desc)
                        
                # --- EXECUTIVE COMPLIANCE REPORT SUMMARY ---
                    st.divider()
                    st.subheader("📋 Executive Compliance Summary")
                    
                    # Initialize generation triggers in state memory
                    if "generate_audit" not in st.session_state:
                        st.session_state.generate_audit = False
                        
                    # Interactive Generation Buttons Layout
                    b_col1, b_col2 = st.columns(2)
                    with b_col1:
                        if st.button("🚀 Click Here to Generate Audit Report", use_container_width=True):
                            st.session_state.generate_audit = True
                    with b_col2:
                        if st.button("🔄 Regenerate Remediation Blueprint", use_container_width=True):
                            st.session_state.generate_audit = True # Triggers fresh re-run compilation
                            
                    if st.session_state.generate_audit:
                        with st.spinner("Compiling structural compliance metrics..."):
                            report_prompt = f"""
                            You are a Lead Corporate Information Security Officer (CISO). 
                            Analyze the following metadata findings extracted from a scanned corporate document and generate a professional, structured compliance audit report.
                            
                            FINDINGS METADATA:
                            - Risk Classification Tier: {risk_level}
                            - PAN Cards Found: {len(found_pans)}
                            - Aadhaar Numbers Found: {len(found_aadhaars)}
                            - Emails Found: {len(found_emails)}
                            - Phone Numbers Found: {len(found_phones)}
                            - Credit Cards Found: {len(found_cards)}
                            - Bank IFSC Codes Found: {len(found_ifscs)}
                            - API Keys/Secrets Found: {len(found_api_keys)}
                            - Employee IDs Found: {len(found_emp_ids)}
                            - Confidential Phrases Found: {len(found_confidential)}
                            
                            Format your output with clean Markdown headings exactly like this:
                            ### 1️⃣ Compliance Observations
                            [Provide text based on compliance data regulations]
                            ### 2️⃣ Security Risks
                            [Provide text outlining data safety risks]
                            ### 3️⃣ Suggested Remediation Steps
                            [Provide clear numbered action steps]
                            """
                            report_response = model.generate_content(report_prompt)
                            st.info(report_response.text)
    
    
# # MODERN 2026 LANGCHAIN IMPORTS (Bypasses langchain.chains entirely)
#         from langchain_text_splitters import CharacterTextSplitter
#         from langchain_openai import OpenAIEmbeddings, ChatOpenAI
#         from langchain_community.vectorstores import FAISS
#         from langchain_core.prompts import ChatPromptTemplate
#         from langchain_core.output_parsers import StrOutputParser
        
#         user_question = st.text_input("Ask a question about this audited document:")
        
#         if user_question and redacted_text:
#             with st.spinner("Processing request..."):
#                 try:
#                     # 1. Chunking text for vector processing
#                     text_splitter = CharacterTextSplitter(separator="\n", chunk_size=500, chunk_overlap=50)
#                     chunks = text_splitter.split_text(redacted_text)
                    
#                     # 2. Setting up FAISS indexing local store
#                     embeddings = OpenAIEmbeddings()
#                     vector_db = FAISS.from_texts(chunks, embeddings)
                    
#                     # 3. Search relevant text context manually
#                     relevant_docs = vector_db.similarity_search(user_question, k=3)
#                     context_text = "\n\n".join([doc.page_content for doc in relevant_docs])
                    
#                     # 4. Construct direct LCEL pipeline
#                     llm = ChatOpenAI(model="gpt-3.5-turbo", temperature=0)
                    
#                     system_prompt = (
#                         "Answer the user's question based strictly on the provided context below.\n"
#                         "If you do not know the answer, say that you cannot find it.\n\n"
#                         "Context:\n{context}"
#                     )
#                     prompt = ChatPromptTemplate.from_messages([
#                         ("system", system_prompt),
#                         ("human", "{input}"),
#                     ])
                    
#                     # Direct execution chain construction
#                     chain = prompt | llm | StrOutputParser()
                    
#                     response = chain.invoke({"context": context_text, "input": user_question})
                    
#                     st.success("🤖 System Answer:")
#                     st.write(response)
#                 except Exception as e:
#                     st.error(f"Execution Error: {e}




                # ---------------------------------------------------------------------
                # ➡️ RIGHT COLUMN SIDE: Interactive Chat Window (Sticky Workspace)
                # ---------------------------------------------------------------------
                with col_right:
                    st.subheader("💬 Chat with your Document")
                    
                    # 1. Initialize conversational message state memory if not present
                    if "chat_history" not in st.session_state:
                        st.session_state.chat_history = []
                    if st.button("🗑️ Clear Chat History", use_container_width=True):
                        st.session_state.chat_history = []
                        st.rerun()
                    # 🔥 UI FIX: Create a fixed-height scrollable window for the history bubbles
                    # This keeps all the content inside a compact card that scrolls internally!
                    chat_container = st.container(height=400, border=True)
                    
                    # Render previous message logs inside our scrollable box
                    with chat_container:
                        for message in st.session_state.chat_history:
                            with st.chat_message(message["role"]):
                                st.write(message["content"])
                    
                    # 2. Dynamic Bottom Chat Input Bar (Now sits stably underneath the scroll box)
                    user_question = st.chat_input("Ask a question about this audited document...")
                    
                    if user_question:
                        # Display user's question instantly inside the container view
                        with chat_container:
                            with st.chat_message("user"):
                                st.write(user_question)
                        
                        st.session_state.chat_history.append({"role": "user", "content": user_question})
                        
                        if redacted_text:
                            with st.spinner("AI is thinking..."):
                                chat_prompt = f"""
                                You are a strict data compliance assistant. Answer the user's question based ONLY on the provided document context below.
                                If the answer cannot be found in the text, say "I cannot find that information in the document."
                                Note: Sensitive data has been securely redacted with placeholders.
                                
                                Document Context:
                                {redacted_text}
                                
                                User Question: {user_question}
                                """
                                response = model.generate_content(chat_prompt)
                                ai_answer = response.text
                                
                                # Display AI response inside the scroll container
                                with chat_container:
                                    with st.chat_message("assistant"):
                                        st.write(ai_answer)
                                
                                st.session_state.chat_history.append({"role": "assistant", "content": ai_answer})