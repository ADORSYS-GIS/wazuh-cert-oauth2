{{/*
Common annoations
*/}}
{{- define "common.annotations.standard" -}}
    {{- $result := dict -}}
    {{- if and (hasKey . "customAnnotations") (hasKey . "context") -}}
        {{- $result = (include "common.tplvalues.merge" (dict "values" (list .customAnnotations .context.Values.commonAnnotations) "context" .context)) -}}
    {{- else if and $.Values $.Values.commonAnnotations -}}
        {{- $result = include "common.tplvalues.render" (dict "value" $.Values.commonAnnotations "context" $) -}}
    {{- end -}}

    {{- if gt (len $result) 2 -}}
        {{ $result }}
    {{- end -}}
{{- end -}}
