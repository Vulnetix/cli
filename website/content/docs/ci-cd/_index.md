---
title: CI/CD Integrations
weight: 4
---

Integrate Vulnetix into your CI/CD pipelines for automated security assessment.

Start with the [Subcommand Reference]({{< relref "subcommands" >}}) — it covers installing, authenticating, choosing an output flag, and gating a build. Every platform page below assumes it.

## Reference

{{< cards >}}
  {{< card link="subcommands" title="Subcommand Reference for CI" subtitle="What each scan writes, which output flag it takes, how to gate a build." >}}
  {{< card link="gha-command" title="GHA Command" subtitle="GitHub Actions artifact upload command." >}}
{{< /cards >}}

## Primary platforms

{{< cards >}}
  {{< card link="github-actions" title="GitHub Actions" subtitle="Native action, artifact collection, GitHub Releases." >}}
  {{< card link="gitlab-ci" title="GitLab CI/CD" subtitle="Quickstart to CI/CD Components, with GitLab Releases." >}}
  {{< card link="bitbucket" title="Bitbucket Pipelines" subtitle="Bitbucket Pipelines integration." >}}
  {{< card link="azure-devops" title="Azure DevOps" subtitle="Azure Pipelines integration." >}}
  {{< card link="jenkins" title="Jenkins" subtitle="Declarative and scripted pipelines." >}}
  {{< card link="docker" title="Docker" subtitle="Run the CLI in a container." >}}
  {{< card link="podman" title="Podman" subtitle="Rootless, daemonless, SELinux-aware." >}}
  {{< card link="kubernetes" title="Kubernetes" subtitle="Jobs and CronJobs with secretKeyRef." >}}
  {{< card link="go-cli" title="Local / Go CLI" subtitle="Your machine, before you push." >}}
{{< /cards >}}

## Other CI systems

{{< cards >}}
  {{< card link="circleci" title="CircleCI" >}}
  {{< card link="buildkite" title="Buildkite" >}}
  {{< card link="travisci" title="Travis CI" >}}
  {{< card link="drone" title="Drone CI" >}}
  {{< card link="tekton" title="Tekton" >}}
  {{< card link="awscodebuild" title="AWS CodeBuild" >}}
  {{< card link="gcloudbuild" title="Google Cloud Build" >}}
  {{< card link="harness" title="Harness CI" >}}
  {{< card link="codefresh" title="Codefresh" >}}
  {{< card link="teamcity" title="TeamCity" >}}
  {{< card link="bamboo" title="Bamboo" >}}
  {{< card link="argo" title="Argo Workflows" >}}
  {{< card link="woodpecker" title="Woodpecker CI" >}}
  {{< card link="gitea" title="Gitea Actions" >}}
  {{< card link="forgejo" title="Forgejo Actions" >}}
  {{< card link="spacelift" title="Spacelift" >}}
  {{< card link="semaphoreci" title="Semaphore CI" >}}
  {{< card link="buddy" title="Buddy" >}}
  {{< card link="earthly" title="Earthly" >}}
  {{< card link="dagger" title="Dagger" >}}
  {{< card link="depot" title="Depot" >}}
{{< /cards >}}
