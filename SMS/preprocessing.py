import re
import nltk
from nltk.corpus import stopwords
from nltk.stem import WordNetLemmatizer

# Environment Setup
nltk.download('stopwords', quiet=True)
nltk.download('wordnet', quiet=True)

stop_words = set(stopwords.words('english'))
lemmatizer = WordNetLemmatizer()

def preprocess_text(text):
    """Cleans and lemmatizes input text for ML processing."""
    if not isinstance(text, str):
        return ""
    
    text = text.lower()
    # Remove special characters and digits
    text = re.sub(r'[^a-z\s]', ' ', text)
    words = text.split()
    
    # Remove stopwords and apply lemmatization
    processed_words = [
        lemmatizer.lemmatize(word) for word in words if word not in stop_words
    ]
    
    return ' '.join(processed_words)