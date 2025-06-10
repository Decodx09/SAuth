pipeline {
    agent any
    tools {
        nodejs "node20"
    }
    environment {
        APP_PORT = 9000
        NODE_ENV = 'production'
        AWS_REGION = 'us-east-1'
    }
    stages {
        stage('Checkout') {
            steps {
                git branch: 'main', 
                url: 'https://github.com/Decodx09/SAuth',
                credentialsId: 'github-creds'
            }
        }
        stage('Install') {
            steps {
                sh 'npm ci --no-audit'
            }
        }
        stage('Test') {
            steps {
                sh 'npm test'
                junit 'test-results/**/*.xml'  // Publish test reports
            }
        }
        stage('Build') {
            steps {
                sh 'npm run build'
                archiveArtifacts artifacts: 'dist/**/*'  // Save build artifacts
            }
        }
        stage('Docker Build') {
            steps {
                script {
                    docker.build("your-username/node-app:${env.BUILD_ID}")
                }
            }
        }
        stage('Deploy to AWS') {
            steps {
                sshagent(['aws-ssh-key']) {
                    sh """
                    ssh -o StrictHostKeyChecking=no ubuntu@${DEPLOY_SERVER} '
                    cd /var/www/node-app
                    git pull
                    npm ci --only=production
                    pm2 restart ecosystem.config.js
                    '
                    """
                }
            }
        }
    }
    post {
        always {
            cleanWs()  // Clean workspace
            slackSend(color: 'good', message: "Build ${BUILD_NUMBER} completed!")
        }
        failure {
            emailext body: 'Build failed!', subject: 'Jenkins Build Failed', to: 'team@example.com'
        }
    }
}