pipeline {
  agent {
    node {
      label 'ubuntu-slave'
    }

  }
  stages {
    stage('Build & Test & Publish') {
      steps {
        sh './gradlew --info clean incrementPatch test jar install javadoc artifactoryPublish'
      }
    }
  }
  environment {
    JAVA_HOME = '/home/jenkins/tools/jdk-11.0.1'
  }
}