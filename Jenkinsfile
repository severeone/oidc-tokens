pipeline {
  agent {
    node {
      label 'ubuntu-slave'
    }

  }
  stages {
    stage('Build & Test & Publish') {
      steps {
        rtServer(id: "maven.gokernel.com", url: "http://maven.gokernel.com/artifactory", username: "admin", password: "trusynagolove07")
        rtGradleDeployer(id: "deployer", serverId: "maven.gokernel.com", repo: "gradle-release-local")
        rtGradleResolver(id: "resolver", serverId: "maven.gokernel.com", repo: "gradle-release")
        rtGradleRun(usesPlugin: true, tool: "5.5", useWrapper: true, rootDir: ".", buildFile: "build.gradle", tasks: "--info clean incrementPatch test jar install javadoc artifactoryPublish", resolverId: "resolver", deployerId: "deployer")
      }
    }
  }
  environment {
    JAVA_HOME = '/home/jenkins/tools/jdk-11.0.1'
  }
}
