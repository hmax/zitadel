variable "GITHUB_SHA" {
  default = "latest"
}

variable "REGISTRY" {
  default = "ghcr.io/zitadel"
}

group "all" {
  targets = ["build", "output", "lint", "image", "unit"]
}

group "build" {
  targets = ["console-build", "core-build"]
}

group "output" {
  targets = ["console-output", "core-output"]
}

group "lint" {
  targets = ["console-lint", "core-lint"]
}

group "image" {
  targets = ["console-image", "core-image"]
}

group "unit" {
  targets = ["core-unit"]
}

target "_console" {
  dockerfile = "Dockerfile.console"
  context = "."
  contexts = {
    node = "docker-image://node:22"
    nginx = "docker-image://nginx:1.27-alpine"
  }
}

target "console" {
  name     = "console-${tgt}"
  inherits = ["_console"]
  matrix = {
    tgt = ["build", "output", "lint", "image"]
  }
  output = {
    "build"  = ["type=cacheonly"]
    "output" = ["type=local,dest=.build/console"]
    "lint"   = ["type=cacheonly"]
    "image"   = ["type=docker"]
  }[tgt]
  tags = {
    "build"  = []
    "output" = []
    "lint"   = []
    "image"   = ["${REGISTRY}/console:${GITHUB_SHA}"]
  }[tgt]
  cache-to = {
    "build"  =  ["type=gha,ignore-error=true,mode=max,scope=console-${tgt}"]
    "output" =  ["type=gha,ignore-error=true,mode=max,scope=console-${tgt}"]
    "lint"   =  ["type=gha,ignore-error=true,mode=max,scope=console-${tgt}"]
    "image"   = ["type=gha,ignore-error=true,mode=max,scope=console-${tgt}"]
  }[tgt]
    cache-from = {
    "build"  =  ["type=gha,scope=console-${tgt}"]
    "output" =  ["type=gha,scope=console-${tgt}"]
    "lint"   =  ["type=gha,scope=console-${tgt}"]
    "image"   = ["type=gha,scope=console-${tgt}"]
  }[tgt]
  target = tgt
}

target "_core" {
  dockerfile = "Dockerfile.core"
  context = "."
  contexts = {
    golang = "docker-image://golang:1.24"
    console = "target:console-output"
  }
  args = {
    SASS_VERSION      = "1.64.1"
    GOLANG_CI_VERSION = "1.64.5"
  }
  #platforms = ["linux/amd64", "linux/arm64"]
}

target "core" {
  name     = "core-${tgt}"
  inherits = ["_core"]
  matrix = {
    tgt = ["build", "output", "lint", "image", "unit"]
  }
  output = {
    "build"  = ["type=cacheonly"]
    "output" = ["type=local,dest=.build/core"]
    "lint"   = ["type=cacheonly"]
    "unit"   = ["type=cacheonly"]
    "image"   = ["type=docker"]
  }[tgt]
  tags = {
    "build"  = []
    "output" = []
    "lint"   = []
    "unit"   = []
    "image"   = ["${REGISTRY}/zitadel:${GITHUB_SHA}"]
  }[tgt]
    cache-to = {
    "build"  =  ["type=gha,ignore-error=true,mode=max,scope=core-${tgt}"]
    "output" =  ["type=gha,ignore-error=true,mode=max,scope=core-${tgt}"]
    "lint"   =  ["type=gha,ignore-error=true,mode=max,scope=core-${tgt}"]
    "unit"   =  ["type=gha,ignore-error=true,mode=max,scope=core-${tgt}"]    
    "image"   = ["type=gha,ignore-error=true,mode=max,scope=core-${tgt}"]
  }[tgt]
    cache-from = {
    "build"  =  ["type=gha,scope=core-${tgt}"]
    "output" =  ["type=gha,scope=core-${tgt}"]
    "lint"   =  ["type=gha,scope=core-${tgt}"]
    "unit"   =  ["type=gha,scope=core-${tgt}"]
    "image"   = ["type=gha,scope=core-${tgt}"]
  }[tgt]
  target = tgt
}