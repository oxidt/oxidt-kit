//! VTODO and VEVENT bodies for [`put_ics`](crate::put_ics), built on the
//! [`icalendar`] crate.
//!
//! `stamped` becomes `DTSTAMP`. It is a parameter instead of a read of the
//! clock, so a body depends only on its inputs.

use chrono::{DateTime, Days, Duration, NaiveDate, Utc};
use icalendar::{Calendar, Component, DatePerhapsTime, EventLike, Todo};

/// A point in time as calendars see it: a whole day, or an instant.
///
/// A zone-less local time has no variant here. Convert it to UTC in the
/// timezone you know it was written in before building the body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum When {
    /// All-day: `VALUE=DATE`.
    Date(NaiveDate),
    /// An instant, written in UTC (`…Z`).
    Time(DateTime<Utc>),
}

impl From<When> for DatePerhapsTime {
    fn from(when: When) -> Self {
        match when {
            When::Date(date) => date.into(),
            When::Time(time) => time.into(),
        }
    }
}

/// A calendar holding one VTODO. `priority` is iCalendar's 1 (highest) to 9
/// (lowest).
pub fn todo(
    uid: &str,
    summary: &str,
    description: &str,
    due: Option<When>,
    priority: Option<u32>,
    stamped: DateTime<Utc>,
) -> String {
    let mut todo = Todo::new();
    todo.uid(uid)
        .summary(summary)
        .description(description)
        .timestamp(stamped);
    if let Some(due) = due {
        todo.due(due);
    }
    if let Some(priority) = priority {
        todo.priority(priority);
    }
    Calendar::new().push(todo.done()).done().to_string()
}

/// A calendar holding one VEVENT. Without an `end`, an all-day event lasts
/// its one day and a timed event one hour.
pub fn event(
    uid: &str,
    summary: &str,
    description: &str,
    start: When,
    end: Option<When>,
    location: Option<&str>,
    stamped: DateTime<Utc>,
) -> String {
    let end = end.unwrap_or(match start {
        When::Date(date) => When::Date(date + Days::new(1)),
        When::Time(time) => When::Time(time + Duration::hours(1)),
    });
    let mut event = icalendar::Event::new();
    event
        .uid(uid)
        .summary(summary)
        .description(description)
        .timestamp(stamped)
        .starts(start)
        .ends(end);
    if let Some(location) = location {
        event.location(location);
    }
    Calendar::new().push(event.done()).done().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    const UID: &str = "00000000-0000-0000-0000-000000000000";

    fn stamped() -> DateTime<Utc> {
        "2026-07-01T00:00:00Z".parse().unwrap()
    }

    #[test]
    fn task_becomes_a_vtodo_with_due_and_priority() {
        let due = When::Time("2026-07-08T10:00:00+02:00".parse().unwrap());
        let ics = todo(
            UID,
            "Call Anna about the offer",
            "Call Anna about the offer\nshe wants numbers",
            Some(due),
            Some(1),
            stamped(),
        );
        assert!(ics.contains("BEGIN:VTODO"));
        assert!(ics.contains(&format!("UID:{UID}")));
        assert!(ics.contains("SUMMARY:Call Anna about the offer\r\n"));
        assert!(ics.contains("DUE:20260708T080000Z"));
        assert!(ics.contains("PRIORITY:1"));
        assert!(ics.contains("DTSTAMP:20260701T000000Z"));
    }

    #[test]
    fn all_day_event_ends_the_next_day() {
        let start = When::Date(NaiveDate::from_ymd_opt(2026, 9, 18).unwrap());
        let ics = event(UID, "Offsite", "", start, None, Some("Berlin"), stamped());
        assert!(ics.contains("BEGIN:VEVENT"));
        assert!(ics.contains("SUMMARY:Offsite"));
        assert!(ics.contains("DTSTART;VALUE=DATE:20260918"));
        assert!(ics.contains("DTEND;VALUE=DATE:20260919"));
        assert!(ics.contains("LOCATION:Berlin"));
    }

    #[test]
    fn timed_event_defaults_to_one_hour() {
        let start = When::Time("2026-09-18T07:00:00Z".parse().unwrap());
        let ics = event(UID, "Standup", "", start, None, None, stamped());
        assert!(ics.contains("DTSTART:20260918T070000Z"), "{ics}");
        assert!(ics.contains("DTEND:20260918T080000Z"), "{ics}");
        assert!(!ics.contains("LOCATION"), "{ics}");
    }
}
