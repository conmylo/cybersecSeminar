# Αρχικό dataset
customers = [
    {"name": "Άννα", "email": "anna@example.com", "age": 28},
    {"name": "Κώστας", "email": "kostas@example.com", "age": 35},
    {"name": "Ιωάννα", "email": "ioanna@example.com", "age": 22}
]

# Πίνακας αντιστοίχισης
mapping_table = {}

# Νέος πίνακας με ψευδωνυμοποιημένα δεδομένα
pseudonymized_customers = []

for index, customer in enumerate(customers, start=1):
    user_id = f"USER{index}"

    # Συμπλήρωση του πίνακα αντιστοίχισης
    mapping_table[user_id] = {
        "name": customer["name"],
        "email": customer["email"]
    }

    # Δημιουργία της ψευδωνυμοποιημένης εγγραφής (χωρίς όνομα & email)
    pseudonymized_customers.append({
        "user_id": user_id,
        "age": customer["age"]
    })

print("Πίνακας αντιστοίχισης (mapping table):")
for user_id, real_data in mapping_table.items():
    print(user_id, "->", real_data)

print("\nΨευδωνυμοποιημένα δεδομένα:")
for record in pseudonymized_customers:
    print(record)


# Με την ψευδωνυμοποίηση αφαιρούμε τα άμεσα αναγνωριστικά (όνομα, email)
# από το dataset και τα αντικαθιστούμε με ουδέτερα ψευδώνυμα (USER1 κτλ.).
# Έτσι, σύμφωνα με τον ΓΚΠΔ, μειώνεται ο κίνδυνος παραβίασης της ιδιωτικότητας,
# γιατί τρίτοι που βλέπουν τα δεδομένα δεν μπορούν να ταυτοποιήσουν άμεσα
# τα υποκείμενα χωρίς πρόσβαση στον πίνακα αντιστοίχισης.
