package org.apache.zeppelin.notebook;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;


public class SecureText {
    private static Logger LOGGER = LoggerFactory.getLogger(SecureText.class);

    private Pattern getBlacklist(String lang) {
        String blacklistEnv = "ZEPPELIN_INTERPRETER_" + lang.toUpperCase() + "_BLACKLIST";
        Optional<String> blacklist = Optional.ofNullable(System.getenv(blacklistEnv));
        return blacklist.map(x -> this.buildPattern(x.split(","))).orElse(buildPattern(this.blacklist));
    }

    private String[] blacklist = new String[]{
            "net", "reflect", "reflect", "nio", "io", "hadoop", "Runtime", "ProcessBuilder",
            "socket", "requests", "httplib", "urllib", "system", "subprocess", "popen", "commands", "eval", "exec", "compile"
    };

    private Pattern buildPattern(String[] blacklist) {
        String str = Arrays.stream(blacklist).reduce((x, y) -> x + "|" + y).get();
        return Pattern.compile("(.*\\W+|\\W*)(" + str + ")(\\W+.*|\\W*)", Pattern.DOTALL);
    }

    private String getlang(Paragraph paragraph) {
        String className = paragraph.getIntpText().toLowerCase().trim();
        LOGGER.debug("Security Check On:" + className);
        if (className.contains("py"))
            return "PYTHON";
        if (className.startsWith("r"))
            return "R";
        if (className.startsWith("spark"))
            return "SCALA";
        if (className.contains("dep"))
            return "DEP";
        return "OTHER";
    }

    public void checkIsSecure(Paragraph paragraph) throws RuntimeException {
        String lang = getlang(paragraph);
        Pattern pattern = getBlacklist(lang);
        LOGGER.debug("SECURITY_CHECK:" + paragraph.getScriptText());
        String insecure = System.getenv("ZEPPELIN_INSECURE");
        if (insecure != null && insecure.equalsIgnoreCase("true"))
            return;
        if (paragraph.getScriptText() == null)
            return;
        Matcher matcher = pattern.matcher(paragraph.getScriptText());
        if (matcher.matches()) {
            String noteName = null;
            if (paragraph.getNote() != null)
                noteName = paragraph.getNote().getName();
            LOGGER.info("SECURITY_BREACH:" + matcher.group(2) + ":" + paragraph.getUser() + ":" + noteName + ":" + paragraph.getText());
            String group1;
            if (matcher.group(1).length() > 10)
                group1 = matcher.group(1).substring(matcher.group(1).length() - 10);
            else
                group1 = matcher.group(1);

            String group3;
            if (matcher.group(3).length() > 10)
                group3 = matcher.group(3).substring(matcher.group(3).length() - 10);
            else
                group3 = matcher.group(3);
            throw new RuntimeException("insecure code detected:" + group1 + "[" + matcher.group(2) + "]" + group3);
        }
    }

    public static SecureText secureText() {
        return new SecureText();
    }
}
