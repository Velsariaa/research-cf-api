from flask import Flask, request, jsonify
import pymysql
import pandas as pd
import traceback
import joblib

app = Flask(__name__)

# ---------- DB CONFIG ----------
db_config = {
    'host': 'srv2051.hstgr.io',
    'user': 'u311577524_admin',
    'password': 'Ej@0MZ#*9',
    'database': 'u311577524_research_db',
    'cursorclass': pymysql.cursors.DictCursor
}

print("\n=== APP STARTING ===")
print("Trying to load model files...")

try:
    vectorizer = joblib.load('vectorizer.pkl')
    model = joblib.load('model.pkl')
    print("Model files loaded successfully!")
except Exception as e:
    print("ERROR loading model files!")
    print(e)
    print(traceback.format_exc())

print("=== STARTUP COMPLETE ===\n")


# ---------- HELPER: DB CONNECTION TEST ----------
def get_connection():
    try:
        conn = pymysql.connect(**db_config)
        print("[DB] Connection OK")
        return conn
    except Exception as e:
        print("[DB] CONNECTION ERROR:")
        print(e)
        print(traceback.format_exc())
        return None


# ---------- RESOLVE STUDENT ----------
def resolve_student_id(raw):
    try:
        if raw.isdigit():
            print(f"[resolve_student_id] Using numeric student_id={raw}")
            return int(raw)

        print(f"[resolve_student_id] Searching student_number='{raw}'")

        conn = get_connection()
        if not conn:
            return None

        query = """
        SELECT student_id
        FROM student_information
        WHERE student_number = %s AND student_id <> 0
        ORDER BY student_id DESC
        LIMIT 1
        """
        df = pd.read_sql(query, conn, params=[raw])
        conn.close()

        print("[resolve_student_id] Query result:")
        print(df.head())

        if df.empty:
            print("[resolve_student_id] No match found!")
            return None

        return int(df.iloc[0]['student_id'])

    except Exception as e:
        print("[resolve_student_id] ERROR!")
        print(e)
        print(traceback.format_exc())
        return None


# ---------- FALLBACK RECOS ----------
def fallback_recos(limit=4):
    print("[fallback_recos] Fetching fallback recommendations...")

    try:
        conn = get_connection()
        if not conn:
            return pd.DataFrame()

        query = """
        SELECT tc_id, title, authorone, authortwo,
               colleges_id, program_id, academic_year,
               project_type, views AS read_count
        FROM thesis_capstone
        ORDER BY views DESC
        LIMIT %s
        """
        df = pd.read_sql(query, conn, params=[limit])
        conn.close()

        print("[fallback_recos] Data:")
        print(df.head())

        return df

    except Exception as e:
        print("[fallback_recos] ERROR!")
        print(e)
        print(traceback.format_exc())
        return pd.DataFrame()


# ---------- COLLAB FILTER CORE ----------
def compute_recommendations(student_arg):
    print("\n====== CF START ======")

    student_id = resolve_student_id(student_arg)
    print(f"[CF] Resolved student_id = {student_id}")

    if student_id is None:
        print("[CF] No student found → using fallback only.")
        fb = fallback_recos(limit=4)
        return fb.to_dict(orient="records")

    try:
        conn = get_connection()
        if not conn:
            print("[CF] Cannot connect to DB → fallback")
            return fallback_recos(limit=4).to_dict(orient="records")

        # Load student_reads
        query_reads = """
        SELECT student_id, tc_id
        FROM student_reads
        """
        reads = pd.read_sql(query_reads, conn)
        print("[CF] student_reads:")
        print(reads.head())

        if reads.empty:
            print("[CF] No reads table data → fallback")
            conn.close()
            return fallback_recos(limit=4).to_dict(orient="records")

        # Load approved theses for filtering
        q_approved = """
        SELECT ts.tc_id
        FROM thesis_submission ts
        WHERE ts.status = 'Approved'
        """
        approved = pd.read_sql(q_approved, conn)
        print("[CF] approved tc_id:")
        print(approved.head())

        conn.close()

        # ----- CF LOGIC -----

        # Build user-item matrix
        matrix = reads.pivot_table(index="student_id",
                                   columns="tc_id",
                                   aggfunc=len,
                                   fill_value=0)

        print("[CF] User-item matrix sample:")
        print(matrix.head())

        if student_id not in matrix.index:
            print("[CF] Student has no reads → fallback")
            fb = fallback_recos(limit=4)
            return fb.to_dict(orient="records")

        # Compute similarity using dot product
        target = matrix.loc[student_id]
        similarity = matrix.dot(target)

        print("[CF] Similarity Series:")
        print(similarity.head())

        # Remove self
        similarity = similarity.drop(student_id)

        # Pick top 4 similar users
        top_users = similarity.sort_values(ascending=False).head(4).index.tolist()
        print(f"[CF] Top similar users: {top_users}")

        # Get the theses they read
        recommended_ids = set(
            reads[reads['student_id'].isin(top_users)]['tc_id'].tolist()
        )

        print(f"[CF] Raw recommended tc_id = {recommended_ids}")

        if not recommended_ids:
            print("[CF] No similar-user items → fallback")
            fb = fallback_recos(limit=4)
            return fb.to_dict(orient="records")

        # Filter approved
        approved_set = set(approved['tc_id'].tolist())
        recommended_ids = recommended_ids & approved_set

        print(f"[CF] Approved filtered tc_id = {recommended_ids}")

        if not recommended_ids:
            print("[CF] None approved → fallback")
            fb = fallback_recos(limit=4)
            return fb.to_dict(orient="records")

        # Finally pull their metadata
        conn = get_connection()
        query_meta = """
        SELECT tc_id, title, authorone, authortwo,
               colleges_id, program_id, academic_year,
               project_type,
               (SELECT COUNT(*) FROM student_reads WHERE tc_id = t.tc_id) AS read_count
        FROM thesis_capstone t
        WHERE tc_id IN (%s)
        """ % ",".join(["%s"] * len(recommended_ids))

        details = pd.read_sql(query_meta, conn, params=list(recommended_ids))
        conn.close()

        print("[CF] Final metadata:")
        print(details.head())

        # If still empty
        if details.empty:
            print("[CF] Metadata empty → fallback")
            fb = fallback_recos(limit=4)
            return fb.to_dict(orient="records")

        # Limit to 4
        final_df = details.head(4)
        print("[CF] FINAL OUTPUT:")
        print(final_df)

        return final_df.to_dict(orient="records")

    except Exception as e:
        print("[CF] ERROR during calculation!")
        print(e)
        print(traceback.format_exc())

        fb = fallback_recos(limit=4)
        return fb.to_dict(orient="records")


# ---------- API ENDPOINT ----------
@app.route("/recommend")
def recommend():
    print("\n=== /recommend HIT ===")
    student_arg = request.args.get("student_id", "").strip()

    print(f"[API] student_id param = '{student_arg}'")

    recs = compute_recommendations(student_arg)

    print("[API] FINAL JSON RESPONSE:")
    print(recs)

    return jsonify(recs)


@app.route("/")
def home():
    return jsonify({"msg": "CF API running"})

