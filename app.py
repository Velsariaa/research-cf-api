from flask import Flask, request, jsonify
import pymysql
import joblib
import pandas as pd

app = Flask(__name__)

# MySQL connection config
db_config = {
    'host': '127.0.0.1',
    'user': 'root',
    'password': '',
    'database': 'research_db',
    'cursorclass': pymysql.cursors.DictCursor
}

# Load vectorizer and model
vectorizer = joblib.load('vectorizer.pkl')
model = joblib.load('model.pkl')  # If unused, remove this line

@app.route('/search', methods=['POST'])
def search():
    data = request.get_json()
    query = data.get('query', '')
    if not query:
        return jsonify([])

    # Connect to database
    conn = pymysql.connect(**db_config)
    try:
        with conn.cursor() as cursor:
            cursor.execute("""
                SELECT tc.title, tc.authorone, tc.authortwo, tc.authorthree,
                       tc.colleges_id, p.program, c.colleges AS college
                FROM thesis_capstone tc
                JOIN thesis_submission ts USING(tc_id)
                JOIN student_information si USING(student_id)
                JOIN program p USING(program_id)
                JOIN colleges c ON si.colleges_id = c.colleges_id
                WHERE ts.status = 'Approved'
            """)
            rows = cursor.fetchall()
    finally:
        conn.close()

    # Create DataFrame and compute similarity
    df = pd.DataFrame(rows)
    df['text'] = df[['title', 'authorone', 'authortwo', 'authorthree']].fillna('').agg(' '.join, axis=1)

    corpus_vec = vectorizer.transform(df['text'])
    q_vec = vectorizer.transform([query])
    scores = (corpus_vec @ q_vec.T).toarray().flatten()

    df['score'] = scores
    top = df.nlargest(5, 'score')
    results = top[['title', 'college', 'program']].to_dict(orient='records')
    return jsonify(results)

if __name__ == '__main__':
    app.run(debug=True)
