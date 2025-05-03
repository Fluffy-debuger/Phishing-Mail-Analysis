from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib
import pandas as pd

df=pd.read_csv('D:\Py_workspace\AI\MailSupiciousDectections\models\phishing_email.csv')
X_train, X_test, y_train, y_test = train_test_split(df['text_combined'], df['label'], test_size=0.2, random_state=42)
vectorizer = TfidfVectorizer(stop_words='english', max_features=5000)
X_train_vect = vectorizer.fit_transform(X_train)
X_test_vect = vectorizer.transform(X_test)
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train_vect, y_train)
y_pred = model.predict(X_test_vect)
print(classification_report(y_test, y_pred))

joblib.dump(model, './/models//phishing_model.pkl')
joblib.dump(vectorizer, './/models//tfidf_vectorizer.pkl')
