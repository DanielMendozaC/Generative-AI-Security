import streamlit as st
import tempfile
import os
import numpy as np
from langchain_community.document_loaders import PyPDFLoader
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_community.embeddings import SentenceTransformerEmbeddings
from langchain_community.vectorstores import Chroma
from langchain_ollama import ChatOllama
from langchain.chains import RetrievalQA

st.set_page_config(page_title="RAG Demo", page_icon="📚", layout="wide")

st.title("🔍 RAG (Retrieval-Augmented Generation) Demo")
st.markdown("""
This application demonstrates how Retrieval-Augmented Generation works step-by-step.
Upload a PDF document, and then ask questions about it to see how RAG retrieves relevant information and generates answers.
""")

# Initialize session state
if 'vectorstore' not in st.session_state:
    st.session_state.vectorstore = None
if 'documents_loaded' not in st.session_state:
    st.session_state.documents_loaded = False
if 'chunks_created' not in st.session_state:
    st.session_state.chunks_created = False
if 'embeddings_created' not in st.session_state:
    st.session_state.embeddings_created = False
if 'vectorstore_ready' not in st.session_state:
    st.session_state.vectorstore_ready = False

# Sidebar for document upload
with st.sidebar:
    st.header("📄 Document Upload")
    uploaded_file = st.file_uploader("Upload a PDF file", type=["pdf"])

    if uploaded_file is not None and not st.session_state.documents_loaded:
        progress_text = st.empty()
        progress_bar = st.progress(0)

        # Step 1: Load PDF
        st.subheader("Step 1: Document Loading")
        progress_text.text("Loading PDF document...")
        progress_bar.progress(10)

        # Save uploaded file to temporary location
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp_file:
            tmp_file.write(uploaded_file.read())
            tmp_path = tmp_file.name

        # Load PDF using PyPDFLoader
        loader = PyPDFLoader(tmp_path)
        documents = loader.load()
        progress_bar.progress(40)

        # Clean up temp file
        os.unlink(tmp_path)

        st.session_state.documents = documents
        st.session_state.documents_loaded = True
        progress_text.text("✅ Document loaded successfully!")
        st.markdown(f"**Loaded {len(documents)} pages from the PDF.**")

        # Step 2: Text Chunking
        st.subheader("Step 2: Text Chunking")
        progress_text.text("Splitting text into chunks...")
        progress_bar.progress(50)

        text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=1000,
            chunk_overlap=100,
            length_function=len
        )

        chunks = text_splitter.split_documents(documents)
        progress_bar.progress(70)

        st.session_state.chunks = chunks
        st.session_state.chunks_created = True
        progress_text.text("✅ Text chunking completed!")
        st.markdown(f"**Created {len(chunks)} text chunks.**")

        # Step 3: Create Embeddings and Vector Store
        st.subheader("Step 3: Embedding Creation")
        progress_text.text("Creating embeddings and building vector database...")
        progress_bar.progress(80)

        # Use local embeddings with sentence-transformers
        embeddings = SentenceTransformerEmbeddings(model_name="all-MiniLM-L6-v2")
        vectorstore = Chroma.from_documents(chunks, embeddings)
        progress_bar.progress(100)

        st.session_state.vectorstore = vectorstore
        st.session_state.embeddings_created = True
        st.session_state.vectorstore_ready = True
        progress_text.text("✅ Vector database ready!")
        st.markdown("**Vector database created with embeddings.**")

        st.success("🎉 RAG system is now ready! You can ask questions about the document.")

    # Show status
    if st.session_state.documents_loaded:
        st.success("Document Loaded ✅")
    if st.session_state.chunks_created:
        st.success("Text Chunked ✅")
    if st.session_state.embeddings_created:
        st.success("Embeddings Created ✅")
    if st.session_state.vectorstore_ready:
        st.success("Vector Store Ready ✅")

# Main content area
if st.session_state.vectorstore_ready:
    st.header("❓ Ask Questions")

    query = st.text_input("Enter your question about the document:", key="query_input")

    if query:
        col1, col2 = st.columns([1, 1])

        with col1:
            st.subheader("🔍 Retrieved Context")

            # Show retrieval process
            with st.spinner("Searching for relevant information..."):
                retriever = st.session_state.vectorstore.as_retriever(search_kwargs={"k": 3})
                relevant_docs = retriever.get_relevant_documents(query)

            for i, doc in enumerate(relevant_docs, 1):
                with st.expander(f"Relevant Chunk {i}"):
                    st.write(doc.page_content[:500] + "..." if len(doc.page_content) > 500 else doc.page_content)

        with col2:
            st.subheader("🤖 Generated Answer")

            # Create QA chain
            with st.spinner("Generating answer..."):
                # Use local Ollama with phi:latest model
                llm = ChatOllama(model="phi:latest", temperature=0)
                qa_chain = RetrievalQA.from_chain_type(
                    llm=llm,
                    chain_type="stuff",
                    retriever=st.session_state.vectorstore.as_retriever()
                )

                answer = qa_chain.run(query)

            st.write(answer)

else:
    if uploaded_file is None:
        st.info("👆 Upload a PDF document using the sidebar to get started.")
    else:
        st.warning("Processing document... Please wait while the RAG system is being prepared.")

# Enhanced sections for detailed RAG visualization
if st.session_state.vectorstore_ready:
    tab1, tab2, tab3 = st.tabs(["🔍 Similarity Search Details", "🧠 Embeddings in ChromaDB", "📚 How RAG Works"])

    with tab1:
        st.header("Similarity Search Algorithm")
        if query and relevant_docs:
            st.markdown("### How Cosine Similarity Works")
            st.markdown("""
            **Cosine Similarity** measures the angle between two vectors in a high-dimensional space.
            A smaller angle = higher similarity = closer to 1.

            **Formula:** cos(θ) = (A · B) / (|A| × |B|)
            where A and B are vectors, A · B is dot product, |A| is magnitude.
            """)

            # Show query embedding
            embeddings_model = SentenceTransformerEmbeddings(model_name="all-MiniLM-L6-v2")
            query_embedding = embeddings_model.embed_query(query)

            # Show similarities
            distances = []
            for doc in relevant_docs:
                chunk_embedding = embeddings_model.embed_query(doc.page_content)
                # Cosine similarity
                similarity = np.dot(query_embedding, chunk_embedding) / (np.linalg.norm(query_embedding) * np.linalg.norm(chunk_embedding))
                distances.append(similarity)

            st.markdown("### Similarity Scores:")
            for i, (doc, score) in enumerate(zip(relevant_docs, distances), 1):
                st.write(f"**Chunk {i}**: {score:.4f}")
                with st.expander("View calculation"):
                    col1, col2 = st.columns(2)
                    with col1:
                        st.markdown("Query Embedding (first 5 dimensions):")
                        st.code(f"[{', '.join(f'{x:.4f}' for x in query_embedding[:5])}]")
                    with col2:
                        chunk_emb = embeddings_model.embed_query(doc.page_content)
                        st.markdown("Chunk Embedding (first 5 dimensions):")
                        st.code(f"[{', '.join(f'{x:.4f}' for x in chunk_emb[:5])}]")
                    st.markdown(f"**Vector Magnitude Query:** {np.linalg.norm(query_embedding):.4f}")
                    st.markdown(f"**Vector Magnitude Chunk:** {np.linalg.norm(chunk_emb):.4f}")
                    st.markdown(f"**Dot Product:** {np.dot(query_embedding, chunk_emb):.4f}")
        else:
            st.info("Enter a question to see similarity search details.")

    with tab2:
        st.header("Embeddings Storage in ChromaDB")
        st.markdown("""
        ChromaDB stores embeddings as high-dimensional vectors (384 dimensions for all-MiniLM-L6-v2).
        Each text chunk is converted to a numerical representation that captures semantic meaning.
        """)

        if st.session_state.chunks:
            # Show sample embeddings
            embeddings_model = SentenceTransformerEmbeddings(model_name="all-MiniLM-L6-v2")
            sample_chunk = st.session_state.chunks[0].page_content[:200] + "..."
            sample_embedding = embeddings_model.embed_query(sample_chunk)

            st.markdown("### Sample Embedding Vector")
            st.write(f"**Sample Text Chunk:** {sample_chunk}")
            st.markdown("**First 10 dimensions of its embedding:**")
            st.code(f"[{', '.join(f'{x:.4f}' for x in sample_embedding[:10])}]")

            st.markdown("### ChromaDB Storage Structure")
            st.markdown("""
            - **Collection**: Document chunks with their embeddings
            - **Metadata**: Source information, page numbers
            - **IDs**: Unique identifiers for each chunk
            - **Index**: Approximate Nearest Neighbor search index
            - **Distance Metric**: Cosine similarity (L2 distance)
            """)

            # Show collection info
            collection = st.session_state.vectorstore._collection
            st.markdown(f"**Collection Name:** {collection.name}")
            st.markdown(f"**Number of Items:** {collection.count()}")
            st.markdown(f"**Distance Function:** Cosine Similarity")

    with tab3:
        st.markdown("""
        **Retrieval-Augmented Generation (RAG)** is a technique that enhances language models by incorporating external knowledge:

        1. **Document Loading**: The system loads and parses the uploaded document using PyPDFLoader
        2. **Text Chunking**: Document is split into manageable pieces using RecursiveCharacterTextSplitter (1000 chars, 100 overlap)
        3. **Embedding Creation**: Each chunk is converted to a 384-dimensional vector using SentenceTransformers (all-MiniLM-L6-v2)
        4. **Vector Database**: Embeddings stored in ChromaDB with cosine similarity search
        5. **Query Processing**: User query is embedded using the same model
        6. **Retrieval**: ChromaDB performs approximate nearest neighbor search to find most similar chunks
        7. **Generation**: Retrieved context is passed to local Ollama phi:latest model for answer generation

        **Benefits**: Access domain-specific knowledge while providing explainable answers with cited sources.
        """)
else:
    with st.expander("📚 How RAG Works"):
        st.markdown("""
        **Retrieval-Augmented Generation (RAG)** is a technique that enhances language models by incorporating external knowledge:

        1. **Document Loading**: The system loads and parses the uploaded document
        2. **Text Chunking**: The document is split into smaller, manageable pieces
        3. **Embedding Creation**: Each chunk is converted into a numerical vector representation
        4. **Vector Database**: Embeddings are stored in a searchable vector database
        5. **Query Embedding**: User queries are also converted to embeddings
        6. **Retrieval**: The system finds the most similar document chunks to the query
        7. **Generation**: An LLM uses the retrieved context to generate a relevant answer

        This approach allows the model to access current, specific information beyond its training data.
        """)

if __name__ == "__main__":
    st.sidebar.markdown("---")

    # Check if Ollama is configured
    import subprocess
    try:
        result = subprocess.run(["ollama", "list"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0 and "phi" in result.stdout:
            st.sidebar.success("✅ Ollama is running with phi:latest model")
        else:
            st.sidebar.warning("⚠️ Ensure Ollama is running and phi:latest model is available")
    except (subprocess.TimeoutExpired, FileNotFoundError):
        st.sidebar.error("❌ Ollama not found or not running")
        st.sidebar.markdown("**Note**: Install and start Ollama:")
        st.sidebar.code("ollama pull phi:latest")
        st.sidebar.markdown("Then start Ollama service.")
