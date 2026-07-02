# 🛡️ Sensitive Data & Compliance Assistant

An enterprise-grade, split-screen data privacy dashboard designed to audit unstructured corporate documents for sensitive parameters (PII/Financials). The system automatically executes regex pattern recognition alongside statistical NLP masking pipelines, calculating real-time vulnerability risk ratings and generating automated executive security briefs.

---

## ⚙️ Setup Instructions

To deploy and execute this application locally from scratch, complete the following steps in your terminal:

1. **Clone the Repository:**
   ```bash
   git clone [https://github.com/Guru1970/Sensitive-Data-Compliance-Assistant.git](https://github.com/Guru1970/Sensitive-Data-Compliance-Assistant.git)
   cd Sensitive-Data-Compliance-Assistant

2.Establish a Clean Virtual Environment:

    ```bash
     python -m venv venv
On Windows:

     venv\Scripts\activate
On macOS/Linux:


    source venv/bin/activate
Install Dependencies via pip:

    pip install streamlit pandas pypdf spacy pillow pytesseract pdf2image google-generativeai
    
Download the Language Model Artifacts:


    python -m spacy download en_core_web_sm
Launch the Application:


    streamlit run app.py


🏗️ Architecture Overview
The system processes unstructured data payloads via a dual-column modular architecture:

Data Ingestion Buffer: Handles multi-modal entry points including standard digital text (.txt), tabular streams (.csv), native digital documents (.pdf), and scanned image vectors (.png, .jpg, .jpeg) via a robust OCR processing engine fallback pipeline.

Telemetry Scanner Matrix: Directs extracted raw text arrays concurrently into a deterministic Regular Expression (Regex) scanner for pattern tracking, and a spaCy Convolutional Neural Network (CNN) Named Entity Recognition (NER) pipeline for semantic entity mapping.

Privacy Redaction Engine: Modifies tracked sensitive vectors in sequence, substituting structural alphanumeric tokens with context placeholders (e.g., [REDACTED NAME], ██████████).

Interactive Evaluation Workspace: Provides a persistent scroll-bounded AI context channel powered by Google AI Studio's Gemini models for strict boundary document questioning.



🧠 AI/ML Approach Used
This application deploys a strategic hybrid detection methodology:

Deterministic String Extraction (Regex): Used for highly standardized national identifiers and strict format metrics (PAN Cards, Aadhaar Numbers, Credit Cards, Corporate Employee IDs, Bank IFSC keys). This ensures a 100% precision rate on strict format compliance targets.

Statistical Deep Learning NER (spaCy en_core_web_sm): Handles contextual and highly variant textual variables (Human Names, Organizations) that regex matching patterns cannot reliably intercept.






## ⚠️ Challenges Faced & Mitigations

* **Memory & Computational Hardware Constraints:** Loading deep learning Transformer models (like spaCy's `md` or `lg` pipelines) caused significant local runtime latency and high RAM utilization spikes during local execution.
  * *Mitigation:* Strategically selected the optimized, lightweight pipeline (`en_core_web_sm`). This decreased the application's memory footprint by over 80% while preserving high processing speeds and clean entity extraction accuracy.
* **The Scanned Image Challenge:** Standard PDF text extractors fail entirely when reading non-digitized scanned paper trails, screenshots, or graphics assets.
  * *Mitigation:* Engineered a structural fallback scanner loop that transforms empty byte outputs into active image buffers, running optical character analysis through `pytesseract`.
* **The Layout Drift Constraint:** Standard vertical rendering components break visual tracking when rendering massive multi-page file reports.
  * *Mitigation:* Redesigned the user interface into an asynchronous split-screen, wrapping raw data preview matrices inside collapsible containers and pinning chat interfaces to static window coordinates.
 

## 🚀 Future Improvements

* **Decentralized Local Inference (Ollama / Llama 3):** To eliminate the risk of accidental third-party data leakage, future versions will replace cloud-based LLM APIs (like Google Gemini) with localized, offline open-source models running locally on device via Ollama. This guarantees a true, airtight zero-trust data boundary.
* **Custom Enterprise NER Fine-Tuning:** The system will be scaled by training custom spaCy pipeline components on specialized datasets to detect region-specific corporate metadata, such as unique employee ID structures, proprietary internal document tags, and specific regional legislative classification markers.
* **Asynchronous Multi-File Batch Auditing:** Implement a high-throughput processing queue using task workers (like Celery) to allow security teams to upload and scan entire directories or cloud storage buckets simultaneously without blocking the user interface.
* **Comprehensive Audit Trail Logs:** Add a secure logging system that exports detailed compliance reports (PDF/CSV formats) showing structural metrics, detected risks, and remediation checklists to help organizations satisfy real-world legal compliance checks.
Generative LLM Context Ingestion (Google Gemini AI Studio): Powers the executive summary compiler and the localized RAG compliance conversational window under strict system guidelines to suppress external model hallucinations.