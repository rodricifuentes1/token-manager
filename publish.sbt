publishMavenStyle := true

pomIncludeRepository := { _ => false }

publishArtifact in Test := false

bintrayRepository := "RC-releases"

bintrayPackageLabels := Seq("scala", "JWT", "json web token", "token-management", "token-manager")