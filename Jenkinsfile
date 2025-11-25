pipeline {
  agent { docker { image 'python:3.9-slim' } }
  environment {
    PYTHONUNBUFFERED = '1'
  }
  stages {
    stage('Checkout') {
      steps {
        checkout scm
      }
    }
    stage('Install Dependencies') {
      steps {
        sh 'pip install --no-cache-dir -r requirements.txt'
      }
    }
    stage('Run RepoGuard') {
      steps {
        withCredentials([
          string(credentialsId: 'GITHUB_TOKEN', variable: 'GITHUB_TOKEN'),
          string(credentialsId: 'GITLAB_TOKEN', variable: 'GITLAB_TOKEN'),
          string(credentialsId: 'OPENAI_API_KEY', variable: 'OPENAI_API_KEY')
        ]) {
          sh 'python -m src.main'
        }
      }
    }
  }
  post {
    always {
      archiveArtifacts artifacts: '**/repo_guard.log', allowEmptyArchive: true
    }
  }
}

