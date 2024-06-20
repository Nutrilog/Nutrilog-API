## Deploying to Google Cloud Run

To deploy this application to Google Cloud Run with a Google Cloud SQL (MySQL) database, follow these steps:

### Prerequisites

- You have a Google Cloud account and a project set up.
- A Google Cloud SQL (MySQL) instance is set up.

### Step 1: Configure Google Cloud SQL

1. **Create a Cloud SQL Instance:**
   - Go to the Google Cloud Console, navigate to **SQL**, and create a new MySQL instance if you haven't already.
   - Set up the instance with the required configuration, including specifying the instance ID, root password, and region.

2. **Create a Database and User:**
   - After the instance is created, connect to it using the Cloud SQL web UI, `gcloud` CLI, or any MySQL client.
   - Create a new database for your application:
     ```sql
     CREATE DATABASE db_nutrilog;
     ```
### Step 2: Prepare the Application for Deployment

1. **Clone the Repository:**
   - Open your terminal and clone the repository to your local machine:
     ```bash
     git clone https://github.com/fauzanalrafii/capstone.git
     cd capstone
     ```

2. **Install Dependencies:**
   - Navigate to the project directory and install the necessary dependencies:
     ```bash
     npm install
     ```

3. **Modify the Application to Use Cloud SQL:**
   - Create .env file at root folder
   - copy this and Update your database configuration in the application to use environment variables for the database connection:
     ```plaintext
     DB_HOST=<Instance Host>
     DB_USER=root
     DB_PASSWORD=<your_password>
     DB_NAME=db_nutrilog
     ```

   Replace `<Instance Host>` with your actual instance connection name, and other placeholders with your database credentials.
   
4. **Modify Server.js**
   - To deploy with cloud run, we must change the server configuration
   - Change port
     ```
     port: parseInt(process.env.port) || 8080,
     host: '0.0.0.0'
     ```
5. **Create Table on Database**
   - On Cloud Shell, copy and paste this code to initialize a table in database
     ```
     npm db:push
     ```
   - After this, the database is ready to store data

### Step 3: Deploy to Google Cloud Run
1. **Deploy to Cloud Run:**
   - Make Sure in capstone folder
   - Deploy the application to Cloud Run, connecting it to the Cloud SQL instance:
     ```bash
     gcloud run deploy
     ```

3. **Access Your Application:**
   - After the deployment is successful, you will receive a URL where your application is hosted on Google Cloud Run.

### Notes:
- Ensure that the Cloud SQL instance and Cloud Run service are in the same region or allow connections from different regions.

With these steps, you have successfully deployed your application to Google Cloud Run using a Google Cloud SQL (MySQL) database.
