rule ExampleRule
{
    strings:
        $my_text_string = "JSCRIPT%"

    condition:
        $my_text_string
}
