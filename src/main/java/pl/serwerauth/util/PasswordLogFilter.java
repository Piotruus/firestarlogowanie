package pl.serwerauth.util;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.Marker;
import org.apache.logging.log4j.core.Filter;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.Logger;
import org.apache.logging.log4j.core.filter.AbstractFilter;
import org.apache.logging.log4j.message.Message;
import org.apache.logging.log4j.message.ParameterizedMessage;

import java.util.regex.Pattern;

/** Ukrywa w konsoli i logach linie z komendami zawierającymi hasła (/login, /register, ...). */
public final class PasswordLogFilter extends AbstractFilter {

    private static final Pattern SENSITIVE = Pattern.compile(
            "(?i)issued server command:\\s*/?(?:[a-z0-9_.-]+:)?"
                    + "(login|l|zaloguj|register|reg|zarejestruj|changepassword|zmienhaslo|unregister|usunkonto|captcha|kod)(\\s|$)");

    private static Filter.Result check(String text) {
        return text != null && SENSITIVE.matcher(text).find() ? Filter.Result.DENY : Filter.Result.NEUTRAL;
    }

    @Override
    public Filter.Result filter(LogEvent event) {
        Message m = event.getMessage();
        return check(m == null ? null : m.getFormattedMessage());
    }

    @Override
    public Filter.Result filter(Logger logger, Level level, Marker marker, Message msg, Throwable t) {
        return check(msg == null ? null : msg.getFormattedMessage());
    }

    @Override
    public Filter.Result filter(Logger logger, Level level, Marker marker, Object msg, Throwable t) {
        return check(msg == null ? null : msg.toString());
    }

    @Override
    public Filter.Result filter(Logger logger, Level level, Marker marker, String msg, Object... params) {
        if (msg == null) return Filter.Result.NEUTRAL;
        return check(params == null || params.length == 0 ? msg : ParameterizedMessage.format(msg, params));
    }
}
