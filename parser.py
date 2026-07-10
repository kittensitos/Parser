# This is a conceptual example in CBN syntax
filter {
  # Check if jsonPayload.message exists
  if [jsonPayload][message] != "" {
    # Replace the raw message with the content of jsonPayload.message
    mutate {
      replace => {
        "@raw_message" => "%{[jsonPayload][message]}"
      }
    }

    # Now, re-process the extracted message using standard syslog grok patterns
    grok {
      match => {
        "@raw_message" => [
          "%{SYSLOGTIMESTAMP:timestamp} %{SYSLOGHOST:hostname} %{DATA:program}(?:[%{POSINT:pid}])?: %{GREEDYDATA:message_body}"
          # Add other standard syslog patterns as fallbacks
        ]
      }
      overwrite => ["timestamp", "hostname", "program", "pid", "message_body"]
    }

    # Map extracted fields to UDM
    mutate {
      rename => {
        "hostname" => "principal.hostname"
        "program" => "principal.process.file.names"
        "pid" => "principal.process.pid"
        "message_body" => "security_result.description"
      }
    }
    # ... further UDM mapping for timestamp, etc.
  }
}
