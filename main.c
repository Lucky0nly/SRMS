/**
 * Secure Student Management System
 * Single-file implementation with SHA-256 hashing, Role-Based Access Control,
 * Atomic File Operations, and Input Validation.
 * 
 * Compile: gcc -o srms main.c
 * Run: ./srms
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <termios.h>
#include <time.h>

/* ============================ CONSTANTS & DEFINITIONS ============================ */

#define MAX_NAME_LEN 100
#define MAX_USER_LEN 50
#define MAX_PASS_LEN 50
#define SALT_LEN 16
#define HASH_LEN 64 /* SHA-256 produces 64 hex chars */
#define DB_FILE "students.csv"
#define CRED_FILE "credentials.txt"
#define TEMP_FILE "students.tmp"

typedef enum { ROLE_GUEST = 0, ROLE_STAFF = 1, ROLE_ADMIN = 2 } Role;

typedef struct {
    int roll;
    char name[MAX_NAME_LEN];
    float marks;
} Student;

typedef struct {
    char username[MAX_USER_LEN];
    char salt[SALT_LEN + 1];
    char hash[HASH_LEN + 1];
    Role role;
} User;

/* ============================ SHA-256 IMPLEMENTATION ============================ */
/* Minimal SHA-256 implementation for portability without external libraries */

typedef unsigned char BYTE;
typedef unsigned int  WORD;

typedef struct {
	BYTE data[64];
	WORD datalen;
	unsigned long long bitlen;
	WORD state[8];
} SHA256_CTX;

#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))
#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

static const WORD k[64] = {
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

void sha256_transform(SHA256_CTX *ctx, const BYTE data[]) {
	WORD a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];
	for (i = 0, j = 0; i < 16; ++i, j += 4)
		m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
	for ( ; i < 64; ++i)
		m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
	a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
	e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];
	for (i = 0; i < 64; ++i) {
		t1 = h + EP1(e) + CH(e, f, g) + k[i] + m[i];
		t2 = EP0(a) + MAJ(a, b, c);
		h = g; g = f; f = e; e = d + t1;
		d = c; c = b; b = a; a = t1 + t2;
	}
	ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
	ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

void sha256_init(SHA256_CTX *ctx) {
	ctx->datalen = 0;
	ctx->bitlen = 0;
	ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85; ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
	ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c; ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
}

void sha256_update(SHA256_CTX *ctx, const BYTE data[], size_t len) {
	size_t i;
	for (i = 0; i < len; ++i) {
		ctx->data[ctx->datalen] = data[i];
		ctx->datalen++;
		if (ctx->datalen == 64) {
			sha256_transform(ctx, ctx->data);
			ctx->bitlen += 512;
			ctx->datalen = 0;
		}
	}
}

void sha256_final(SHA256_CTX *ctx, BYTE hash[]) {
	WORD i;
	i = ctx->datalen;
	if (ctx->datalen < 56) {
		ctx->data[i++] = 0x80;
		while (i < 56) ctx->data[i++] = 0x00;
	} else {
		ctx->data[i++] = 0x80;
		while (i < 64) ctx->data[i++] = 0x00;
		sha256_transform(ctx, ctx->data);
		memset(ctx->data, 0, 56);
	}
	ctx->bitlen += ctx->datalen * 8;
	ctx->data[63] = ctx->bitlen;
	ctx->data[62] = ctx->bitlen >> 8;
	ctx->data[61] = ctx->bitlen >> 16;
	ctx->data[60] = ctx->bitlen >> 24;
	ctx->data[59] = ctx->bitlen >> 32;
	ctx->data[58] = ctx->bitlen >> 40;
	ctx->data[57] = ctx->bitlen >> 48;
	ctx->data[56] = ctx->bitlen >> 56;
	sha256_transform(ctx, ctx->data);
	for (i = 0; i < 4; ++i) {
		hash[i]      = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 4]  = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 8]  = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
	}
}

/* Helper to get hex string of hash */
void get_sha256_string(const char *input, const char *salt, char *output) {
    SHA256_CTX ctx;
    BYTE hash[32];
    char combined[MAX_PASS_LEN + SALT_LEN + 1];
    
    snprintf(combined, sizeof(combined), "%s%s", salt, input);
    
    sha256_init(&ctx);
    sha256_update(&ctx, (BYTE *)combined, strlen(combined));
    sha256_final(&ctx, hash);

    for(int i = 0; i < 32; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[64] = '\0';
}

/* ============================ UTILITIES ============================ */

void clean_stdin() {
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
}

// Safe string input
void get_input(char *buffer, int size) {
    if (fgets(buffer, size, stdin) != NULL) {
        size_t len = strlen(buffer);
        if (len > 0 && buffer[len - 1] == '\n') {
            buffer[len - 1] = '\0';
        } else {
            // Buffer full, flush rest of line
             int c;
             while ((c = getchar()) != '\n' && c != EOF);
        }
    }
}

// Password masking
void get_password(char *password, int size) {
    struct termios oldt, newt;
    int i = 0;
    int c;

    // Turn off echo
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    while (i < size - 1 && (c = getchar()) != '\n' && c != EOF) {
        password[i++] = c;
    }
    password[i] = '\0';

    // Restore echo
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    printf("\n");
}

void trim_whitespace(char *str) {
    char *end;
    while(isspace((unsigned char)*str)) str++;
    if(*str == 0) return;
    end = str + strlen(str) - 1;
    while(end > str && isspace((unsigned char)*end)) end--;
    end[1] = '\0';
}

void generate_salt(char *salt) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for (int i = 0; i < SALT_LEN; i++) {
        salt[i] = charset[rand() % (sizeof(charset) - 1)];
    }
    salt[SALT_LEN] = '\0';
}

void to_lowercase(char *str, char *dest) {
    for(int i = 0; str[i]; i++) {
        dest[i] = tolower(str[i]);
    }
    dest[strlen(str)] = '\0';
}

/* ============================ FILE IO & LOGIC ============================ */

Role current_role = ROLE_GUEST;

int authenticate() {
    char username[MAX_USER_LEN];
    char password[MAX_PASS_LEN];
    char line[256];
    char file_user[MAX_USER_LEN];
    char file_salt[SALT_LEN + 1];
    char file_hash[HASH_LEN + 1];
    char file_role_str[10];
    char input_hash[HASH_LEN + 1];

    printf("Username: ");
    get_input(username, MAX_USER_LEN);
    printf("Password: ");
    get_password(password, MAX_PASS_LEN);

    FILE *fp = fopen(CRED_FILE, "r");
    if (!fp) {
        printf("Error: Credentials file not found.\n");
        return 0;
    }

    while (fgets(line, sizeof(line), fp)) {
        // Parse: user:salt:hash:role
        // Remove newline
        line[strcspn(line, "\n")] = 0;
        
        char *token = strtok(line, ":");
        if (!token) continue;
        strncpy(file_user, token, MAX_USER_LEN);

        token = strtok(NULL, ":");
        if (!token) continue;
        strncpy(file_salt, token, SALT_LEN + 1);

        token = strtok(NULL, ":");
        if (!token) continue;
        strncpy(file_hash, token, HASH_LEN + 1);

        token = strtok(NULL, ":");
        if (!token) continue;
        strncpy(file_role_str, token, 10);

        if (strcmp(username, file_user) == 0) {
            get_sha256_string(password, file_salt, input_hash);
            if (strcmp(input_hash, file_hash) == 0) {
                if (strcmp(file_role_str, "ADMIN") == 0) current_role = ROLE_ADMIN;
                else if (strcmp(file_role_str, "STAFF") == 0) current_role = ROLE_STAFF;
                else current_role = ROLE_GUEST;
                fclose(fp);
                return 1;
            }
        }
    }

    fclose(fp);
    return 0;
}

// Atomic Add
void add_student() {
    if (current_role < ROLE_STAFF) {
        printf("Access Denied: Insufficient permissions.\n");
        return;
    }

    Student s;
    char buffer[20];

    printf("Enter Roll Number: ");
    get_input(buffer, 20);
    s.roll = atoi(buffer);
    if (s.roll <= 0) {
        printf("Invalid Roll Number.\n");
        return;
    }

    // Check duplicate (naive O(N) check by reading file)
    FILE *chk = fopen(DB_FILE, "r");
    if (chk) {
        char line[256];
        while(fgets(line, sizeof(line), chk)) {
            char *tok = strtok(line, ",");
            if(tok && atoi(tok) == s.roll) {
                printf("Error: Roll number already exists.\n");
                fclose(chk);
                return;
            }
        }
        fclose(chk);
    }

    printf("Enter Name: ");
    get_input(s.name, MAX_NAME_LEN);
    trim_whitespace(s.name);
    if (strlen(s.name) == 0) {
        printf("Name cannot be empty.\n");
        return;
    }

    printf("Enter Marks (0-100): ");
    get_input(buffer, 20);
    s.marks = atof(buffer);
    if (s.marks < 0 || s.marks > 100) {
        printf("Invalid Marks.\n");
        return;
    }

    // Append safely
    FILE *fp = fopen(DB_FILE, "a");
    if (!fp) {
        printf("Error opening database.\n");
        return;
    }
    fprintf(fp, "%d,%s,%.2f\n", s.roll, s.name, s.marks);
    fclose(fp);
    printf("Student added successfully.\n");
}

void view_students() {
    FILE *fp = fopen(DB_FILE, "r");
    if (!fp) {
        printf("No data found.\n");
        return;
    }

    char line[256];
    printf("\n%-10s %-30s %-10s\n", "Roll", "Name", "Marks");
    printf("----------------------------------------------------\n");
    
    while (fgets(line, sizeof(line), fp)) {
        line[strcspn(line, "\n")] = 0;
        if (strlen(line) == 0) continue;

        char *roll_str = strtok(line, ",");
        char *name_str = strtok(NULL, ",");
        char *marks_str = strtok(NULL, ",");

        if (roll_str && name_str && marks_str) {
            printf("%-10s %-30s %-10s\n", roll_str, name_str, marks_str);
        }
    }
    fclose(fp);
}

void search_students() {
    printf("Enter name to search (partial ok): ");
    char query[MAX_NAME_LEN];
    get_input(query, MAX_NAME_LEN);
    char query_lower[MAX_NAME_LEN];
    to_lowercase(query, query_lower);

    FILE *fp = fopen(DB_FILE, "r");
    if (!fp) {
        printf("No data found.\n");
        return;
    }

    char line[256];
    char original_line[256];
    int found = 0;

    printf("\n%-10s %-30s %-10s\n", "Roll", "Name", "Marks");
    printf("----------------------------------------------------\n");

    while (fgets(line, sizeof(line), fp)) {
        strcpy(original_line, line);
        line[strcspn(line, "\n")] = 0;
        
        char *roll_str = strtok(line, ",");
        char *name_str = strtok(NULL, ",");
        char *marks_str = strtok(NULL, ",");

        if (name_str) {
            char name_lower[MAX_NAME_LEN];
            to_lowercase(name_str, name_lower);
            if (strstr(name_lower, query_lower)) {
                printf("%-10s %-30s %-10s\n", roll_str, name_str, marks_str);
                found = 1;
            }
        }
    }
    fclose(fp);
    if (!found) printf("No matches found.\n");
}

/* Atomic Delete / Update Implementation */
void delete_student() {
    if (current_role != ROLE_ADMIN) {
        printf("Access Denied: Only ADMIN can delete.\n");
        return;
    }

    char buffer[20];
    printf("Enter Roll Number to delete: ");
    get_input(buffer, 20);
    int target_roll = atoi(buffer);

    FILE *fp = fopen(DB_FILE, "r");
    if (!fp) {
        printf("Database not found.\n");
        return;
    }

    FILE *temp = fopen(TEMP_FILE, "w");
    if (!temp) {
        printf("Error creating temp file.\n");
        fclose(fp);
        return;
    }

    char line[256];
    char original_line[256];
    int found = 0;

    while (fgets(line, sizeof(line), fp)) {
        strcpy(original_line, line);
        // Copy logic
        char temp_line[256];
        strcpy(temp_line, line);
        
        char *tok = strtok(temp_line, ",");
        int current_roll = tok ? atoi(tok) : -1;

        if (current_roll == target_roll) {
            found = 1;
            // Skip writing this line
        } else {
            fprintf(temp, "%s", original_line); // Write original format
        }
    }

    fclose(fp);
    fclose(temp);

    if (found) {
        if (remove(DB_FILE) == 0 && rename(TEMP_FILE, DB_FILE) == 0) {
            printf("Student deleted successfully.\n");
        } else {
            printf("Error updating database file.\n");
        }
    } else {
        remove(TEMP_FILE);
        printf("Student not found.\n");
    }
}

/* ============================ MIGRATION TOOL (Embedded) ============================ */
void create_default_admin() {
    FILE *fp = fopen(CRED_FILE, "r");
    if (fp) {
        fclose(fp);
        return; // File exists
    }

    // Create default admin:admin
    printf("No credentials file found. Creating default 'admin' user...\n");
    fp = fopen(CRED_FILE, "w");
    if (!fp) return;

    char salt[SALT_LEN + 1];
    generate_salt(salt);
    
    char hash[HASH_LEN + 1];
    get_sha256_string("admin", salt, hash);

    fprintf(fp, "admin:%s:%s:ADMIN\n", salt, hash);
    fclose(fp);
    printf("Created 'admin' with password 'admin'. Please change it immediately.\n");
}

/* ============================ MAIN ============================ */

void menu() {
    while (1) {
        printf("\n=== Student Management System ===\n");
        printf("Logged in as: %s\n", 
            current_role == ROLE_ADMIN ? "ADMIN" : 
            (current_role == ROLE_STAFF ? "STAFF" : "GUEST"));
        printf("1. View Students\n");
        printf("2. Search Students\n");
        if (current_role >= ROLE_STAFF) printf("3. Add Student\n");
        if (current_role == ROLE_ADMIN) printf("4. Delete Student\n");
        printf("5. Logout/Exit\n");
        printf("Choice: ");

        char buffer[10];
        get_input(buffer, 10);
        int choice = atoi(buffer);

        switch (choice) {
            case 1: view_students(); break;
            case 2: search_students(); break;
            case 3: 
                if(current_role >= ROLE_STAFF) add_student(); 
                else printf("Invalid option.\n");
                break;
            case 4: 
                if(current_role == ROLE_ADMIN) delete_student(); 
                else printf("Invalid option.\n");
                break;
            case 5: printf("Goodbye.\n"); return;
            default: printf("Invalid choice.\n");
        }
    }
}

int main() {
    srand(time(NULL));
    create_default_admin(); // Ensure we have a way to login if fresh

    printf("=== LOGIN ===\n");
    if (authenticate()) {
        printf("Login successful!\n");
        menu();
    } else {
        printf("Login failed.\n");
    }
    return 0;
}
